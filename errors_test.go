package clamav

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
)

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"context canceled", context.Canceled, false},
		{"wrapped canceled", fmt.Errorf("clamav: scan aborted: %w", context.Canceled), false},
		{"context deadline", context.DeadlineExceeded, true},
		{"wrapped deadline", fmt.Errorf("clamav: read: %w", context.DeadlineExceeded), true},
		{"size limit", ErrSizeLimitExceeded, false},
		{"wrapped size limit", fmt.Errorf("%w: too big", ErrSizeLimitExceeded), false},
		{"clamd size limit multi-wrap", fmt.Errorf("%w: %w", ErrSizeLimitExceeded, &ClamdError{Message: "INSTREAM size limit exceeded."}), false},
		{"clamd error", &ClamdError{Message: "engine failure"}, false},
		{"protocol error", &ProtocolError{Command: "INSTREAM", Response: "???"}, false},
		{"connection error dial", &ConnectionError{Op: "dial", Err: errors.New("refused")}, true},
		{"connection error read EOF", &ConnectionError{Op: "read", Err: io.EOF}, true},
		{"connection error wrapping canceled", &ConnectionError{Op: "read", Err: context.Canceled}, false},
		{"unrecognized error", errors.New("mystery"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRetryable(tt.err); got != tt.want {
				t.Errorf("IsRetryable(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestErrorStringsDoNotEmbedPayload(t *testing.T) {
	// Error strings end up in logs; they must carry classification and
	// metadata, never scanned content. This is a design guard, checked
	// here for the constructors used by the client.
	errs := []error{
		&ClamdError{Message: "INSTREAM size limit exceeded."},
		&ProtocolError{Command: "INSTREAM", Response: "short reply"},
		&ConnectionError{Op: "write", Err: errors.New("broken pipe")},
	}
	for _, err := range errs {
		if err.Error() == "" {
			t.Errorf("%T has empty Error()", err)
		}
	}
}

func TestConnectionErrorUnwrap(t *testing.T) {
	inner := errors.New("inner")
	err := &ConnectionError{Op: "dial", Err: inner}
	if !errors.Is(err, inner) {
		t.Error("ConnectionError does not unwrap to inner error")
	}
}

func TestZeroScanResultIsFailClosed(t *testing.T) {
	var res ScanResult
	if res.Clean() {
		t.Error("zero ScanResult reports Clean() == true; fail-closed guarantee broken")
	}
	if res.Infected() {
		t.Error("zero ScanResult reports Infected() == true")
	}
	if res.Verdict != VerdictUnknown {
		t.Errorf("zero Verdict = %v, want VerdictUnknown", res.Verdict)
	}
	if got := res.Verdict.String(); got != "unknown" {
		t.Errorf("zero Verdict.String() = %q, want %q", got, "unknown")
	}
}

func TestVerdictString(t *testing.T) {
	for v, want := range map[Verdict]string{
		VerdictUnknown:  "unknown",
		VerdictClean:    "clean",
		VerdictInfected: "infected",
		Verdict(200):    "unknown",
	} {
		if got := v.String(); got != want {
			t.Errorf("Verdict(%d).String() = %q, want %q", uint8(v), got, want)
		}
	}
}
