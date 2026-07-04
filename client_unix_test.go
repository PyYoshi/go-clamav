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
