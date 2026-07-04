package clamav

import (
	"context"
	"errors"
	"fmt"
)

// ErrSizeLimitExceeded reports that a payload exceeded a size limit: either
// the client-side limit configured with WithMaxStreamSize, or clamd's
// StreamMaxLength (clamd replies "INSTREAM size limit exceeded. ERROR").
// Detect it with errors.Is. The error message states which side enforced
// the limit.
//
// A size-limited file has NOT been scanned. Under the fail-closed contract
// it must be rejected, not accepted.
var ErrSizeLimitExceeded = errors.New("clamav: stream size limit exceeded")

// ClamdError reports that clamd itself replied with an "... ERROR" response
// (engine failure, size limit, malformed request, ...). Detect it with
// errors.As. When the underlying cause is a size limit violation the error
// also matches errors.Is(err, ErrSizeLimitExceeded).
type ClamdError struct {
	// Message is the reply with the trailing " ERROR" token removed.
	Message string
}

func (e *ClamdError) Error() string { return fmt.Sprintf("clamav: clamd error: %s", e.Message) }

// ProtocolError reports a clamd reply that does not match the known reply
// grammar. Unknown replies are always errors: the library never guesses a
// verdict from a response it cannot classify (fail-closed).
type ProtocolError struct {
	// Command is the clamd command that was being executed, e.g. "INSTREAM".
	Command string
	// Response is the offending reply, bounded by the internal read limit.
	Response string
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("clamav: unexpected %s response from clamd: %q", e.Command, e.Response)
}

// ConnectionError reports a transport failure (dial, read, or write) while
// talking to clamd. Detect it with errors.As. These are usually transient
// (clamd restarting, socket backlog, network hiccup); see IsRetryable.
type ConnectionError struct {
	// Op is the failing operation: "dial", "read", or "write".
	Op string
	// Err is the underlying transport error.
	Err error
}

func (e *ConnectionError) Error() string { return fmt.Sprintf("clamav: %s: %v", e.Op, e.Err) }
func (e *ConnectionError) Unwrap() error { return e.Err }

// IsRetryable reports whether retrying the failed operation with the same
// input and a fresh context could plausibly succeed.
//
// The library never retries by itself: an io.Reader cannot be replayed, and
// silent retries would double-stream large uploads. Callers that retry must
// re-supply the input (e.g. reopen the file) and should apply a bounded
// backoff.
//
// Retryable: connection failures (ConnectionError) and deadline expiry.
// Not retryable: context.Canceled, ErrSizeLimitExceeded, ClamdError,
// ProtocolError, and anything unrecognized (conservative default).
//
// A verdict of VerdictInfected is a scan result, not an error — it is never
// subject to retry.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, context.Canceled):
		return false
	case errors.Is(err, ErrSizeLimitExceeded):
		return false
	case errors.Is(err, context.DeadlineExceeded):
		return true
	}
	var clamdErr *ClamdError
	var protoErr *ProtocolError
	var connErr *ConnectionError
	switch {
	case errors.As(err, &clamdErr), errors.As(err, &protoErr):
		return false
	case errors.As(err, &connErr):
		return true
	}
	return false
}
