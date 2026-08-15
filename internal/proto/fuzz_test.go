package proto

import (
	"bufio"
	"bytes"
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

// FuzzReadLine checks the bounded single-line reader: it must never panic,
// and every successfully returned line must respect the invariants the
// classifier depends on — bounded length and no embedded terminators.
func FuzzReadLine(f *testing.F) {
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
		{4, append(bytes.Repeat([]byte{'A'}, 4), 0)},   // exactly at the bound
		{4, append(bytes.Repeat([]byte{'A'}, 5), 0)},   // one over
		{16, append(bytes.Repeat([]byte{'A'}, 64), 0)}, // well over
	}
	for _, s := range seeds {
		f.Add(s.max, s.data)
	}
	f.Fuzz(func(t *testing.T, maxSeed uint16, data []byte) {
		max := fuzzMax(maxSeed)
		line, err := ReadLine(bufio.NewReader(bytes.NewReader(data)), max)
		if err != nil {
			return
		}
		if len(line) > max {
			t.Fatalf("line exceeds the read bound: %d > %d", len(line), max)
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
		{4, append(bytes.Repeat([]byte{'B'}, 4), 0)},
		{4, append(bytes.Repeat([]byte{'B'}, 5), 0)},
		{16, append(bytes.Repeat([]byte{'B'}, 64), 0)},
	}
	for _, s := range seeds {
		f.Add(s.max, s.data)
	}
	f.Fuzz(func(t *testing.T, maxSeed uint16, data []byte) {
		max := fuzzMax(maxSeed)
		block, err := ReadBlock(bufio.NewReader(bytes.NewReader(data)), max)
		if err != nil {
			return
		}
		if len(block) > max {
			t.Fatalf("block exceeds the read bound: %d > %d", len(block), max)
		}
		if strings.ContainsRune(block, 0) {
			t.Fatalf("block contains NUL: %q", block)
		}
	})
}
