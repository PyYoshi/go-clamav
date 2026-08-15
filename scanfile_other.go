//go:build !unix

package clamav

import "os"

// openScanTarget opens the scan target. Non-unix platforms have no
// FIFO-open blocking hazard for the paths ScanFile accepts (ADR-0006), so
// a plain open suffices; the caller's fstat re-check remains the
// authoritative type gate.
func openScanTarget(path string) (*os.File, error) {
	// #nosec G304 -- opening the caller-designated scan target is ScanFile's contract
	return os.Open(path)
}
