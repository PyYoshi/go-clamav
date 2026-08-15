//go:build unix

package clamav

import (
	"os"
	"syscall"
)

// openScanTarget opens the scan target without ever blocking on it. A
// plain open of a FIFO with no writer blocks until a writer appears and
// cannot be cancelled by a context, so a path swapped for a FIFO between
// ScanFile's type check and the open would stall the calling goroutine
// (ADR-0006). O_NONBLOCK makes that open return immediately instead; for
// the regular files the caller accepts (via the fstat re-check) the flag
// has no effect on reads, so it is left set.
func openScanTarget(path string) (*os.File, error) {
	// #nosec G304 -- opening the caller-designated scan target is ScanFile's contract
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
