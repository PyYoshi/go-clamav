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
			if trimmed != "OK" && trimmed != "stream: OK" && trimmed != "instream (local): OK" {
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

// FuzzReadLine checks the bounded single-line reader: it must never panic,
// and every successfully returned line must respect the invariants the
// classifier depends on — bounded length and no embedded terminators.
func FuzzReadLine(f *testing.F) {
	seeds := [][]byte{
		[]byte("PONG\x00"),
		[]byte("stream: OK\x00garbage"),
		[]byte("stream: OK\nEvil FOUND\x00"),
		[]byte("PONG\r\n"),
		[]byte(""),
		[]byte("\x00"),
		append(bytes.Repeat([]byte{'A'}, MaxLineResponse), 0),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		line, err := ReadLine(bufio.NewReader(bytes.NewReader(data)), MaxLineResponse)
		if err != nil {
			return
		}
		if len(line) > MaxLineResponse {
			t.Fatalf("line exceeds the read bound: %d bytes", len(line))
		}
		if strings.ContainsAny(line, "\r\n\x00") {
			t.Fatalf("line contains an embedded terminator: %q", line)
		}
	})
}

// FuzzReadBlock checks the bounded multi-line reader: no panics, and a
// successful read is bounded and NUL-free.
func FuzzReadBlock(f *testing.F) {
	seeds := [][]byte{
		[]byte("POOLS: 1\nTHREADS: live 1\nEND\x00"),
		[]byte("STATE: ok\n"),
		[]byte(""),
		[]byte("\x00"),
		append(bytes.Repeat([]byte{'B'}, MaxBlockResponse), 0),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		block, err := ReadBlock(bufio.NewReader(bytes.NewReader(data)), MaxBlockResponse)
		if err != nil {
			return
		}
		if len(block) > MaxBlockResponse {
			t.Fatalf("block exceeds the read bound: %d bytes", len(block))
		}
		if strings.ContainsRune(block, 0) {
			t.Fatalf("block contains NUL: %q", block)
		}
	})
}
