package proto

import (
	"strings"
	"testing"
)

// FuzzParseScanResponse checks that the response parser never panics and
// never drifts toward a permissive classification on arbitrary input.
func FuzzParseScanResponse(f *testing.F) {
	seeds := []string{
		"stream: OK",
		"OK",
		"stream: Eicar-Signature FOUND",
		"instream (local): Eicar-Signature FOUND",
		"INSTREAM size limit exceeded. ERROR",
		"ERROR",
		"stream: Some sig with spaces FOUND",
		"",
		"\x00",
		"stream: OK FOUND",
		"NOT OK",
		strings.Repeat("A", MaxLineResponse),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		got := ParseScanResponse(line)
		switch got.Outcome {
		case OutcomeUnknown, OutcomeClean, OutcomeInfected, OutcomeError:
		default:
			t.Fatalf("invalid outcome %d for %q", got.Outcome, line)
		}
		trimmed := strings.TrimRight(line, " \t\r\n\x00")
		// Fail-closed invariants: "clean" is only ever produced by an
		// exact OK suffix, and any FOUND suffix must classify as infected.
		if got.Outcome == OutcomeClean {
			if trimmed != "OK" && !strings.HasSuffix(trimmed, ": OK") {
				t.Fatalf("clean verdict from non-OK input %q", line)
			}
		}
		if strings.HasSuffix(trimmed, " FOUND") && got.Outcome != OutcomeInfected {
			t.Fatalf("FOUND response %q classified as %d, not infected", line, got.Outcome)
		}
		if got.Outcome == OutcomeInfected && !strings.HasSuffix(trimmed, " FOUND") {
			t.Fatalf("infected verdict without FOUND suffix: %q", line)
		}
	})
}
