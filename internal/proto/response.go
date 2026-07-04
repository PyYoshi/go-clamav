package proto

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

const (
	// MaxLineResponse bounds single-line responses (scan verdicts, PONG,
	// VERSION, ...). A hostile or broken server cannot make us buffer more.
	MaxLineResponse = 4 << 10 // 4 KiB

	// MaxBlockResponse bounds multi-line responses (STATS).
	MaxBlockResponse = 1 << 20 // 1 MiB
)

// ErrResponseTooLarge indicates the server sent a response exceeding the
// read limit. Treated as a protocol violation (fail-closed).
var ErrResponseTooLarge = errors.New("response exceeds read limit")

// ReadLine reads a single response line terminated by NUL (z-format) or,
// leniently, by '\n', up to max bytes of content. Trailing '\r' and '\n'
// are trimmed. EOF after at least one byte returns the data read so far
// (clamd may close the connection right after replying); EOF with no data
// is returned as io.EOF so callers can classify "closed without response".
func ReadLine(br *bufio.Reader, max int) (string, error) {
	buf := make([]byte, 0, 64)
	for {
		b, err := br.ReadByte()
		if err != nil {
			if err == io.EOF && len(buf) > 0 {
				return trimEOL(string(buf)), nil
			}
			return "", err
		}
		if b == 0 || b == '\n' {
			return trimEOL(string(buf)), nil
		}
		if len(buf) >= max {
			return "", ErrResponseTooLarge
		}
		buf = append(buf, b)
	}
}

// ReadBlock reads a multi-line response (STATS) terminated by NUL or EOF,
// up to max bytes. Newlines are preserved as part of the content.
func ReadBlock(br *bufio.Reader, max int) (string, error) {
	buf := make([]byte, 0, 512)
	for {
		b, err := br.ReadByte()
		if err != nil {
			if err == io.EOF && len(buf) > 0 {
				return string(buf), nil
			}
			return "", err
		}
		if b == 0 {
			return string(buf), nil
		}
		if len(buf) >= max {
			return "", ErrResponseTooLarge
		}
		buf = append(buf, b)
	}
}

func trimEOL(s string) string {
	return strings.TrimRight(s, "\r\n")
}

// Outcome classifies a scan response. The zero value is OutcomeUnknown so
// that an unhandled or malformed response can never read as "clean".
type Outcome uint8

const (
	OutcomeUnknown Outcome = iota
	OutcomeClean
	OutcomeInfected
	OutcomeError
)

// ScanResponse is the parsed form of a scan verdict line.
type ScanResponse struct {
	Outcome   Outcome
	Signature string // set when Outcome == OutcomeInfected
	Message   string // ERROR message (Outcome == OutcomeError) or raw line (OutcomeUnknown)
	SizeLimit bool   // true when the ERROR indicates a size limit violation
}

// ParseScanResponse classifies a single scan response line.
//
// The parser is deliberately prefix-agnostic: clamd historically used
// different reply prefixes ("stream: ...", "instream (local): ...", or a
// file path for path-based scans), so classification relies on the reply
// suffix only:
//
//	"<prefix>: <signature> FOUND"     -> OutcomeInfected
//	"<message> ERROR"                 -> OutcomeError
//	"OK" or "<stream prefix>: OK"     -> OutcomeClean
//	anything else                     -> OutcomeUnknown (fail-closed)
//
// FOUND is checked before ERROR and OK: when a response is ambiguous the
// parser must never prefer the more permissive classification. Signature
// names may contain spaces; only the final " FOUND" token is stripped.
func ParseScanResponse(line string) ScanResponse {
	line = strings.TrimRight(line, " \t\r\n\x00")
	switch {
	case strings.HasSuffix(line, " FOUND"):
		sig := strings.TrimSuffix(line, " FOUND")
		if i := strings.Index(sig, ": "); i >= 0 {
			sig = sig[i+2:]
		}
		sig = strings.TrimSpace(sig)
		// An empty signature is protocol-weird but still a detection:
		// classify as infected rather than unknown so quarantine-style
		// callers treat it as such. Never as clean.
		return ScanResponse{Outcome: OutcomeInfected, Signature: sig}
	case line == "ERROR":
		return ScanResponse{Outcome: OutcomeError}
	case strings.HasSuffix(line, " ERROR"):
		msg := strings.TrimSpace(strings.TrimSuffix(line, " ERROR"))
		return ScanResponse{
			Outcome:   OutcomeError,
			Message:   msg,
			SizeLimit: isSizeLimitMessage(msg),
		}
	case line == "OK":
		return ScanResponse{Outcome: OutcomeClean}
	case strings.HasSuffix(line, ": OK"):
		// Trust only the OK forms INSTREAM can actually produce:
		// "stream: OK" and the legacy "instream (local): OK". An OK with
		// any other prefix (e.g. a path — this client never issues SCAN)
		// stays unknown rather than being accepted as a verdict.
		prefix := strings.TrimSuffix(line, ": OK")
		if strings.Contains(strings.ToLower(prefix), "stream") {
			return ScanResponse{Outcome: OutcomeClean}
		}
		return ScanResponse{Outcome: OutcomeUnknown, Message: line}
	default:
		return ScanResponse{Outcome: OutcomeUnknown, Message: line}
	}
}

func isSizeLimitMessage(msg string) bool {
	return strings.Contains(strings.ToLower(msg), "size limit exceeded")
}
