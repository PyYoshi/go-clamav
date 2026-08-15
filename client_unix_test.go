//go:build unix

package clamav

import (
	"context"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PyYoshi/go-clamav/internal/clamdtest"
)

// TestScanFileRejectsFIFO guards the pre-open type check: os.Open on a FIFO
// with no writer blocks forever, so ScanFile must reject it from stat alone,
// quickly, and without dialing clamd.
func TestScanFileRejectsFIFO(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	c := newClient(t, fake.Addr)

	path := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	start := time.Now()
	res, err := c.ScanFile(context.Background(), path)
	assertFailClosed(t, res, err)
	if !strings.Contains(err.Error(), "regular file") {
		t.Errorf("error = %v, want regular-file rejection", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("FIFO rejection took %v; ScanFile blocked on open", elapsed)
	}
}

// TestOpenScanTargetDoesNotBlockOnFIFO guards the authoritative layer of
// the FIFO defense: even when the pre-open type check is raced (the path
// swapped for a FIFO after it passed), the non-blocking open returns
// immediately and the descriptor re-check rejects the FIFO (ADR-0006).
func TestOpenScanTargetDoesNotBlockOnFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	start := time.Now()
	f, err := openScanTarget(path)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("open took %v; openScanTarget blocked on a writer-less FIFO", elapsed)
	}
	if err != nil {
		// A platform that fails the non-blocking FIFO open outright is
		// equally fail-closed.
		t.Logf("openScanTarget failed fast: %v", err)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("fstat: %v", err)
	}
	if err := checkScanTarget(NoSizeLimit, path, fi); err == nil {
		t.Fatal("descriptor re-check accepted a FIFO")
	}
}
