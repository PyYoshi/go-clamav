// Package mockscan shows how to test code that uses go-clamav without a
// running clamd: define a minimal interface at your own boundary and hand
// it a test double (see mockscan_test.go).
//
// go-clamav deliberately exports no scanner interface (see
// docs/adr/0004-no-exported-scanner-interface.md). Go interfaces are
// satisfied implicitly, so the smallest interface you define yourself is
// already satisfied by *clamav.Client — and your code depends only on the
// methods it actually uses.
package mockscan

import (
	"context"
	"errors"
	"fmt"
	"io"

	clamav "github.com/PyYoshi/go-clamav"
)

// scanner is the consumer-defined interface: the smallest surface this
// package needs. *clamav.Client satisfies it implicitly; nothing in the
// library had to change for that.
type scanner interface {
	Scan(ctx context.Context, r io.Reader) (clamav.ScanResult, error)
}

// Compile-time proof that *clamav.Client satisfies scanner. If the method
// signature ever drifted, this file would stop compiling.
var _ scanner = (*clamav.Client)(nil)

// ErrRejected is returned for every upload that must not be accepted —
// detections and scan failures alike (fail-closed).
var ErrRejected = errors.New("upload rejected")

// UploadGate decides whether an uploaded file may be accepted, applying the
// library's fail-closed contract: accept only on a clean verdict, reject on
// a detection, and reject on ANY scan error, because an error means the
// verdict is unknown.
type UploadGate struct {
	Scanner scanner
}

// Accept scans the upload and returns nil only when it may be accepted.
func (g *UploadGate) Accept(ctx context.Context, upload io.Reader) error {
	res, err := g.Scanner.Scan(ctx, upload)
	if err != nil {
		// The verdict is unknown here — the upload must not pass.
		// IsRetryable distinguishes failures worth retrying with the
		// re-supplied input (clamd restarting, deadline expiry) from
		// permanent ones (size limit, protocol errors).
		if clamav.IsRetryable(err) {
			return fmt.Errorf("%w: scan failed, retry later: %w", ErrRejected, err)
		}
		return fmt.Errorf("%w: scan failed: %w", ErrRejected, err)
	}
	// Gate on Clean(), not on "not infected": anything that is not
	// positively clean stays out.
	if !res.Clean() {
		return fmt.Errorf("%w: malware detected (%s)", ErrRejected, res.Signature)
	}
	return nil
}
