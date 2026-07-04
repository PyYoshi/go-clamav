package proto

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

func br(s string) *bufio.Reader { return bufio.NewReader(strings.NewReader(s)) }

func TestReadLine(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{"NUL terminated", "PONG\x00", "PONG", nil},
		{"newline terminated", "PONG\n", "PONG", nil},
		{"CRLF terminated", "PONG\r\n", "PONG", nil},
		{"EOF after data", "PONG", "PONG", nil},
		{"EOF no data", "", "", io.EOF},
		{"empty line NUL", "\x00", "", nil},
		{"stops at first terminator", "stream: OK\x00garbage", "stream: OK", nil},
		{"trailing newline before NUL tolerated", "PONG\n\x00", "PONG", nil},
		{"embedded newline rejected", "stream: OK\nEvil FOUND\x00", "", ErrMalformedReply},
		{"embedded CR rejected", "stream: OK\rjunk\x00", "", ErrMalformedReply},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadLine(br(tt.input), MaxLineResponse)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadLineTooLarge(t *testing.T) {
	_, err := ReadLine(br(strings.Repeat("a", 100)+"\x00"), 10)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("error = %v, want ErrResponseTooLarge", err)
	}
}

func TestReadBlock(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{"multiline NUL terminated", "POOLS: 1\nTHREADS: live 1\nEND\x00", "POOLS: 1\nTHREADS: live 1\nEND", nil},
		{"EOF terminated", "STATE: ok\n", "STATE: ok\n", nil},
		{"EOF no data", "", "", io.EOF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadBlock(br(tt.input), MaxBlockResponse)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadBlockTooLarge(t *testing.T) {
	_, err := ReadBlock(br(strings.Repeat("a", 100)+"\x00"), 10)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("error = %v, want ErrResponseTooLarge", err)
	}
}

func TestParseScanResponse(t *testing.T) {
	tests := []struct {
		name string
		line string
		want ScanResponse
	}{
		{
			"clean modern prefix",
			"stream: OK",
			ScanResponse{Outcome: OutcomeClean},
		},
		{
			"clean bare",
			"OK",
			ScanResponse{Outcome: OutcomeClean},
		},
		{
			"clean legacy instream prefix",
			"instream (local): OK",
			ScanResponse{Outcome: OutcomeClean},
		},
		{
			"path-prefixed OK is not trusted (SCAN is never issued)",
			"/tmp/upload.bin: OK",
			ScanResponse{Outcome: OutcomeUnknown, Message: "/tmp/upload.bin: OK"},
		},
		{
			"unknown prefix OK is not trusted",
			"garbage: OK",
			ScanResponse{Outcome: OutcomeUnknown, Message: "garbage: OK"},
		},
		{
			"infected eicar",
			"stream: Eicar-Signature FOUND",
			ScanResponse{Outcome: OutcomeInfected, Signature: "Eicar-Signature"},
		},
		{
			"infected official db name",
			"stream: Win.Test.EICAR_HDB-1 FOUND",
			ScanResponse{Outcome: OutcomeInfected, Signature: "Win.Test.EICAR_HDB-1"},
		},
		{
			"infected multi-word signature",
			"stream: Some sig with spaces FOUND",
			ScanResponse{Outcome: OutcomeInfected, Signature: "Some sig with spaces"},
		},
		{
			"infected legacy prefix",
			"instream (local): Eicar-Signature FOUND",
			ScanResponse{Outcome: OutcomeInfected, Signature: "Eicar-Signature"},
		},
		{
			"infected signature containing colon-space",
			"stream: Sig: With.Colon FOUND",
			ScanResponse{Outcome: OutcomeInfected, Signature: "Sig: With.Colon"},
		},
		{
			"infected no prefix",
			"Eicar-Signature FOUND",
			ScanResponse{Outcome: OutcomeInfected, Signature: "Eicar-Signature"},
		},
		{
			"infected empty signature stays infected",
			"stream:  FOUND",
			ScanResponse{Outcome: OutcomeInfected, Signature: ""},
		},
		{
			"size limit error",
			"INSTREAM size limit exceeded. ERROR",
			ScanResponse{Outcome: OutcomeError, Message: "INSTREAM size limit exceeded.", SizeLimit: true},
		},
		{
			"generic error",
			"stream: Some engine failure ERROR",
			ScanResponse{Outcome: OutcomeError, Message: "stream: Some engine failure"},
		},
		{
			"bare error",
			"ERROR",
			ScanResponse{Outcome: OutcomeError},
		},
		{
			"found wins over trailing error wording",
			"stream: Nasty ERROR sig FOUND",
			ScanResponse{Outcome: OutcomeInfected, Signature: "Nasty ERROR sig"},
		},
		{
			"error suffix wins over embedded found",
			"stream: FOUND something ERROR",
			ScanResponse{Outcome: OutcomeError, Message: "stream: FOUND something"},
		},
		{
			"unknown garbage",
			"???",
			ScanResponse{Outcome: OutcomeUnknown, Message: "???"},
		},
		{
			"unknown empty",
			"",
			ScanResponse{Outcome: OutcomeUnknown},
		},
		{
			"unknown OK without separator is not clean",
			"NOT OK",
			ScanResponse{Outcome: OutcomeUnknown, Message: "NOT OK"},
		},
		{
			"signature named OK is infected not clean",
			"stream: OK FOUND",
			ScanResponse{Outcome: OutcomeInfected, Signature: "OK"},
		},
		{
			"trailing whitespace tolerated",
			"stream: OK \r\n",
			ScanResponse{Outcome: OutcomeClean},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseScanResponse(tt.line)
			if got != tt.want {
				t.Errorf("ParseScanResponse(%q) = %+v, want %+v", tt.line, got, tt.want)
			}
		})
	}
}
