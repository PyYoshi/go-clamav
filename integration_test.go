//go:build integration

package clamav_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	clamav "github.com/PyYoshi/go-clamav"
	"github.com/PyYoshi/go-clamav/internal/clamdtest"
)

// Integration tests run against a real clamd (see docker/compose.yaml and
// `make integration`). Each address is exercised with the same suite:
//
//	CLAMAV_TCP_ADDR  e.g. tcp://127.0.0.1:3310
//	CLAMAV_UNIX_ADDR e.g. unix:///path/to/docker/run/clamd.sock
//
// Unset addresses are skipped. The clamd under test uses the EICAR-only
// database and StreamMaxLength 5M from docker/clamd/.
func integrationAddrs(t *testing.T) map[string]string {
	t.Helper()
	addrs := map[string]string{}
	if a := os.Getenv("CLAMAV_TCP_ADDR"); a != "" {
		addrs["tcp"] = a
	}
	if a := os.Getenv("CLAMAV_UNIX_ADDR"); a != "" {
		addrs["unix"] = a
	}
	if len(addrs) == 0 {
		t.Skip("CLAMAV_TCP_ADDR / CLAMAV_UNIX_ADDR not set; run via `make integration`")
	}
	return addrs
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestIntegration(t *testing.T) {
	for network, addr := range integrationAddrs(t) {
		t.Run(network, func(t *testing.T) {
			c, err := clamav.New(addr)
			if err != nil {
				t.Fatalf("New(%q): %v", addr, err)
			}

			t.Run("Ping", func(t *testing.T) {
				if err := c.Ping(testCtx(t)); err != nil {
					t.Fatalf("Ping() = %v", err)
				}
			})

			t.Run("Version", func(t *testing.T) {
				v, err := c.Version(testCtx(t))
				if err != nil {
					t.Fatalf("Version() = %v", err)
				}
				if !strings.HasPrefix(v, "ClamAV ") {
					t.Errorf("Version() = %q, want ClamAV prefix", v)
				}
				t.Logf("clamd version: %s", v)
			})

			t.Run("Stats", func(t *testing.T) {
				s, err := c.Stats(testCtx(t))
				if err != nil {
					t.Fatalf("Stats() = %v", err)
				}
				if !strings.Contains(s, "END") {
					t.Errorf("Stats() = %q, want block ending with END", s)
				}
			})

			t.Run("ScanClean", func(t *testing.T) {
				payload := make([]byte, 1<<20)
				if _, err := rand.Read(payload); err != nil {
					t.Fatal(err)
				}
				res, err := c.Scan(testCtx(t), bytes.NewReader(payload))
				if err != nil {
					t.Fatalf("Scan() = %v", err)
				}
				if !res.Clean() {
					t.Errorf("random payload = %+v, want clean", res)
				}
			})

			t.Run("ScanEICAR", func(t *testing.T) {
				res, err := c.Scan(testCtx(t), bytes.NewReader(clamdtest.EICAR()))
				if err != nil {
					t.Fatalf("Scan() = %v", err)
				}
				if !res.Infected() {
					t.Fatalf("EICAR result = %+v, want infected", res)
				}
				// Our test DB names it Eicar-Test-Signature; official DBs
				// use names like Win.Test.EICAR_HDB-1. Both contain "eicar".
				if !strings.Contains(strings.ToLower(res.Signature), "eicar") {
					t.Errorf("Signature = %q, want an EICAR signature", res.Signature)
				}
			})

			t.Run("ScanFileEICAR", func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "eicar.bin")
				if err := os.WriteFile(path, clamdtest.EICAR(), 0o600); err != nil {
					t.Fatal(err)
				}
				res, err := c.ScanFile(testCtx(t), path)
				if err != nil {
					t.Fatalf("ScanFile() = %v", err)
				}
				if !res.Infected() {
					t.Errorf("result = %+v, want infected", res)
				}
			})

			t.Run("ServerSizeLimit", func(t *testing.T) {
				// 6 MiB exceeds the test clamd's StreamMaxLength (5M). The
				// client-side limit is disabled to prove the server-side
				// rejection is caught. clamd replies with the size-limit
				// ERROR and closes; over TCP the RST can occasionally eat
				// that reply, in which case a retryable ConnectionError is
				// the accepted (still fail-closed) outcome.
				unlimited, err := clamav.New(addr, clamav.WithMaxStreamSize(clamav.NoSizeLimit))
				if err != nil {
					t.Fatal(err)
				}
				res, err := unlimited.Scan(testCtx(t), bytes.NewReader(make([]byte, 6<<20)))
				if err == nil {
					t.Fatalf("oversized scan succeeded: %+v; want error", res)
				}
				if res != (clamav.ScanResult{}) {
					t.Fatalf("non-zero result %+v alongside error %v", res, err)
				}
				var connErr *clamav.ConnectionError
				if !errors.Is(err, clamav.ErrSizeLimitExceeded) && !errors.As(err, &connErr) {
					t.Errorf("error = %v, want ErrSizeLimitExceeded (or ConnectionError on TCP RST)", err)
				}
			})

			t.Run("ClientSizeLimit", func(t *testing.T) {
				limited, err := clamav.New(addr, clamav.WithMaxStreamSize(1024))
				if err != nil {
					t.Fatal(err)
				}
				_, err = limited.Scan(testCtx(t), bytes.NewReader(make([]byte, 2048)))
				if !errors.Is(err, clamav.ErrSizeLimitExceeded) {
					t.Errorf("error = %v, want ErrSizeLimitExceeded", err)
				}
			})

			t.Run("ConcurrentScans", func(t *testing.T) {
				cc, err := clamav.New(addr, clamav.WithMaxConcurrentScans(4))
				if err != nil {
					t.Fatal(err)
				}
				ctx := testCtx(t)
				var wg sync.WaitGroup
				errs := make([]error, 16)
				for i := range errs {
					wg.Add(1)
					go func() {
						defer wg.Done()
						payload := make([]byte, 256<<10)
						if _, err := rand.Read(payload); err != nil {
							errs[i] = err
							return
						}
						res, err := cc.Scan(ctx, bytes.NewReader(payload))
						if err == nil && !res.Clean() {
							err = errors.New("random payload not clean: " + res.Raw)
						}
						errs[i] = err
					}()
				}
				wg.Wait()
				for i, err := range errs {
					if err != nil {
						t.Errorf("concurrent scan %d: %v", i, err)
					}
				}
			})

			t.Run("Reload", func(t *testing.T) {
				if err := c.Reload(testCtx(t)); err != nil {
					t.Fatalf("Reload() = %v", err)
				}
				// clamd must come back to a scannable state afterwards.
				deadline := time.Now().Add(30 * time.Second)
				for {
					res, err := c.ScanBytes(testCtx(t), clamdtest.EICAR())
					if err == nil && res.Infected() {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("clamd did not recover after RELOAD: res=%+v err=%v", res, err)
					}
					time.Sleep(500 * time.Millisecond)
				}
			})
		})
	}
}
