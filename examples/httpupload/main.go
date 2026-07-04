// Command httpupload is a reference implementation of fail-closed upload
// scanning: an HTTP endpoint that accepts a file only after clamd has
// scanned it and returned a clean verdict. Any scan failure rejects the
// upload — an unreachable or overloaded scanner never lets a file through.
//
//	go run ./examples/httpupload -addr tcp://127.0.0.1:3310 -listen :8080
//	curl -F file=@document.pdf http://127.0.0.1:8080/upload
//
// Responses:
//
//	200 accepted            (scan completed, clean)
//	400 malware detected    (scan completed, signature matched)
//	413 file too large      (client- or server-side size limit)
//	503 scan unavailable    (verdict unknown; Retry-After set when retryable)
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	clamav "github.com/PyYoshi/go-clamav"
)

const maxUploadBytes = 25 << 20 // keep equal to clamd's StreamMaxLength

func main() {
	addr := flag.String("addr", "unix:///run/clamav/clamd.sock", "clamd address (unix:// or tcp://)")
	listen := flag.String("listen", "127.0.0.1:8080", "HTTP listen address")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	scanner, err := clamav.New(*addr,
		clamav.WithMaxStreamSize(maxUploadBytes),
		// Below clamd's MaxThreads: bursts queue here (bounded by the
		// request context) instead of overloading the scanner.
		clamav.WithMaxConcurrentScans(4),
	)
	if err != nil {
		logger.Error("configuring scanner", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /upload", uploadHandler(scanner, logger))
	// Readiness includes the scanner: without clamd every upload would be
	// rejected anyway, so stop advertising readiness (fail-closed applies
	// to infrastructure signals too).
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := scanner.Ping(ctx); err != nil {
			http.Error(w, "scanner unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	logger.Info("listening", "addr", *listen, "clamd", *addr)
	server := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func uploadHandler(scanner *clamav.Client, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()

		// Defense in depth: cap the request body before it reaches the
		// scanner at all.
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes+(1<<20))
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "missing multipart field 'file'", http.StatusBadRequest)
			return
		}
		defer file.Close()

		result, err := scanner.Scan(ctx, file)
		switch {
		case errors.Is(err, clamav.ErrSizeLimitExceeded):
			http.Error(w, "file too large to scan", http.StatusRequestEntityTooLarge)

		case err != nil:
			// Verdict UNKNOWN. The one rule that must never be broken:
			// this branch must not accept the file.
			logger.Error("scan failed", "file", header.Filename, "error", err)
			if clamav.IsRetryable(err) {
				w.Header().Set("Retry-After", "10")
			}
			http.Error(w, "scan unavailable, upload rejected", http.StatusServiceUnavailable)

		case result.Infected():
			// Log the signature for the audit trail; do not echo scanner
			// details back to the (untrusted) uploader.
			logger.Warn("malware detected",
				"file", header.Filename, "signature", result.Signature)
			http.Error(w, "upload rejected", http.StatusBadRequest)

		default:
			// Clean: only now may the file be moved to permanent storage.
			logger.Info("upload accepted", "file", header.Filename, "bytes", header.Size)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("accepted\n"))
		}
	}
}
