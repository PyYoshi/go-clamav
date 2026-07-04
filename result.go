package clamav

// Verdict is the outcome of a completed scan.
//
// The zero value is VerdictUnknown, which is never produced by a successful
// scan: it exists so that a ScanResult obtained alongside a non-nil error
// (always the zero ScanResult) can never be mistaken for a clean verdict.
type Verdict uint8

const (
	// VerdictUnknown means no verdict was obtained. It is the zero value
	// and must never be treated as clean.
	VerdictUnknown Verdict = iota
	// VerdictClean means the scan completed and clamd found no signature.
	VerdictClean
	// VerdictInfected means the scan completed and clamd matched a signature.
	VerdictInfected
)

// String returns "unknown", "clean", or "infected".
func (v Verdict) String() string {
	switch v {
	case VerdictClean:
		return "clean"
	case VerdictInfected:
		return "infected"
	default:
		return "unknown"
	}
}

// ScanResult is the outcome of a successfully completed scan. Methods on
// Scan-family functions return the zero ScanResult whenever they return a
// non-nil error, so its Verdict is VerdictUnknown in every error case.
type ScanResult struct {
	// Verdict is the scan outcome. Never VerdictUnknown on a nil error.
	Verdict Verdict
	// Signature is the matched signature name (e.g. "Win.Test.EICAR_HDB-1").
	// Set only when Verdict is VerdictInfected; it may be empty if clamd
	// reported a detection without a usable name.
	Signature string
	// Raw is the verbatim clamd reply line, for logging and diagnostics.
	// Do not parse it to derive a verdict; use Verdict.
	Raw string
}

// Clean reports whether the scan completed with no detection.
func (r ScanResult) Clean() bool { return r.Verdict == VerdictClean }

// Infected reports whether the scan completed with a detection.
func (r ScanResult) Infected() bool { return r.Verdict == VerdictInfected }
