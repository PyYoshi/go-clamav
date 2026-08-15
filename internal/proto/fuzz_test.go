package proto

import (
	"bufio"
	"bytes"
	"errors"
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
		"instream (local): OK",
		"STREAM: OK",
		"foostream: OK",
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
		// Fail-closed invariants: "clean" is only ever produced by the
		// exact OK allowlist (ADR-0005), and any FOUND suffix must
		// classify as infected.
		if got.Outcome == OutcomeClean {
			if trimmed != "OK" && trimmed != "stream: OK" {
				t.Fatalf("clean verdict outside the exact OK allowlist: %q", line)
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

// fuzzMax maps a fuzzed seed to a small read bound. The readers' bound is
// the load-bearing part (AGENTS.md invariant 3), but a target that always
// passed the production MaxLineResponse / MaxBlockResponse would need the
// engine to synthesize a 4 KiB (or 1 MiB) input before it could reach the
// ErrResponseTooLarge branch at all. Deriving the bound from the input
// lets small inputs straddle it, and keeps the seed corpus small enough
// that the engine does not stall mutating giant entries.
func fuzzMax(seed uint16) int { return int(seed%256) + 1 }

// contentLen is how many bytes a reader buffers for this input: everything
// before the first NUL, or the whole input when there is none. Both readers
// reject once that count exceeds max, so it is what the bound applies to.
func contentLen(data []byte) int {
	if i := bytes.IndexByte(data, 0); i >= 0 {
		return i
	}
	return len(data)
}

// assertBoundEnforced pins AGENTS.md invariant 3 for the reply readers:
// content longer than the bound must fail with ErrResponseTooLarge, never
// be returned. Checking the input length rather than the returned string
// matters — ReadLine trims trailing CR/LF, so an unbounded read of
// "AAAA\r\n" under a 4-byte bound would return a 4-character line and slip
// past a length assertion on the result alone.
func assertBoundEnforced(t *testing.T, data []byte, max, got int, err error) {
	t.Helper()
	over := contentLen(data) > max
	switch {
	case err == nil && over:
		t.Fatalf("read %d bytes of content under a %d-byte bound without error", contentLen(data), max)
	case err != nil && over && !errors.Is(err, ErrResponseTooLarge):
		t.Fatalf("%d bytes of content under a %d-byte bound: err = %v, want ErrResponseTooLarge",
			contentLen(data), max, err)
	case err == nil && got > max:
		t.Fatalf("result exceeds the read bound: %d > %d", got, max)
	}
}

// FuzzReadLine checks the bounded single-line reader: it must never panic,
// and every successfully returned line must respect the invariants the
// classifier depends on — bounded length and no embedded terminators.
func FuzzReadLine(f *testing.F) {
	// Seeds carry the raw seed, not the bound: fuzzMax maps seed n to a
	// bound of n%256+1, so seed 3 means a 4-byte bound.
	seeds := []struct {
		max  uint16
		data []byte
	}{
		{64, []byte("PONG\x00")},
		{64, []byte("stream: OK\x00garbage")},
		{64, []byte("stream: OK\nEvil FOUND\x00")},
		{64, []byte("PONG\r\n")},
		{1, []byte("")},
		{1, []byte("\x00")},
		{3, append(bytes.Repeat([]byte{'A'}, 4), 0)},   // exactly at the 4-byte bound
		{3, append(bytes.Repeat([]byte{'A'}, 5), 0)},   // one over
		{3, []byte("AAAA\r\n")},                        // one over, but trimmed back to the bound
		{15, append(bytes.Repeat([]byte{'A'}, 64), 0)}, // well over the 16-byte bound
	}
	for _, s := range seeds {
		f.Add(s.max, s.data)
	}
	f.Fuzz(func(t *testing.T, maxSeed uint16, data []byte) {
		max := fuzzMax(maxSeed)
		line, err := ReadLine(bufio.NewReader(bytes.NewReader(data)), max)
		assertBoundEnforced(t, data, max, len(line), err)
		if err != nil {
			return
		}
		if strings.ContainsAny(line, "\r\n\x00") {
			t.Fatalf("line contains an embedded terminator: %q", line)
		}
	})
}

// FuzzReadBlock checks the bounded multi-line reader: no panics, and a
// successful read is bounded and NUL-free. Newlines are content here, so
// only the bound and the NUL terminator are invariants.
func FuzzReadBlock(f *testing.F) {
	seeds := []struct {
		max  uint16
		data []byte
	}{
		{64, []byte("POOLS: 1\nTHREADS: live 1\nEND\x00")},
		{64, []byte("STATE: ok\n")},
		{1, []byte("")},
		{1, []byte("\x00")},
		{3, append(bytes.Repeat([]byte{'B'}, 4), 0)},   // exactly at the 4-byte bound
		{3, append(bytes.Repeat([]byte{'B'}, 5), 0)},   // one over
		{15, append(bytes.Repeat([]byte{'B'}, 64), 0)}, // well over the 16-byte bound
	}
	for _, s := range seeds {
		f.Add(s.max, s.data)
	}
	f.Fuzz(func(t *testing.T, maxSeed uint16, data []byte) {
		max := fuzzMax(maxSeed)
		block, err := ReadBlock(bufio.NewReader(bytes.NewReader(data)), max)
		assertBoundEnforced(t, data, max, len(block), err)
		if err != nil {
			return
		}
		if strings.ContainsRune(block, 0) {
			t.Fatalf("block contains NUL: %q", block)
		}
	})
}
