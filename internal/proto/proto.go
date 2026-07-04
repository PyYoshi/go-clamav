// Package proto implements the clamd wire protocol primitives: z-format
// command encoding, INSTREAM chunk framing, and response parsing.
//
// The package is transport-agnostic: it operates on io.Reader/io.Writer and
// leaves connection management, deadlines, and context handling to the caller.
package proto

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	chunkHeaderSize = 4

	// MaxChunkSize is a sanity cap for the INSTREAM chunk size. Chunk
	// lengths are encoded as uint32, but allowing arbitrarily large chunks
	// would only waste memory without improving throughput.
	MaxChunkSize = 16 << 20 // 16 MiB

	// DefaultChunkSize is used when the caller passes a non-positive chunk
	// size. Callers are expected to validate configuration upfront; this is
	// a defensive fallback only.
	DefaultChunkSize = 32 << 10 // 32 KiB
)

// ErrSizeLimitExceeded is returned by StreamAll when the source would exceed
// the configured byte limit. The chunk that would cross the limit is not
// written to the sink.
var ErrSizeLimitExceeded = errors.New("stream size limit exceeded")

// SourceError wraps a failure to read from the caller-supplied data source
// (e.g. the io.Reader passed to Scan). It never indicates a clamd problem.
type SourceError struct {
	Err error
}

func (e *SourceError) Error() string { return "reading scan source: " + e.Err.Error() }
func (e *SourceError) Unwrap() error { return e.Err }

// SinkError wraps a failure to write to clamd. Callers should attempt to
// read a pending ERROR response after observing a SinkError, because clamd
// replies and closes the connection when a stream exceeds StreamMaxLength.
type SinkError struct {
	Err error
}

func (e *SinkError) Error() string { return "writing to clamd: " + e.Err.Error() }
func (e *SinkError) Unwrap() error { return e.Err }

// EncodeCommand returns the z-format (NUL-terminated) encoding of a clamd
// command, e.g. EncodeCommand("PING") == "zPING\x00". The z form is used for
// every command so that responses are unambiguously NUL-delimited.
func EncodeCommand(name string) []byte {
	b := make([]byte, 0, len(name)+2)
	b = append(b, 'z')
	b = append(b, name...)
	b = append(b, 0)
	return b
}

// StreamAll reads r to EOF and writes it to w as INSTREAM chunks: a 4-byte
// big-endian length prefix followed by the payload, terminated by a
// zero-length chunk. It returns the number of payload bytes written.
//
// maxBytes limits the payload size; a negative value means unlimited. When
// the source would exceed maxBytes, StreamAll stops before writing the
// offending chunk and returns ErrSizeLimitExceeded, so no truncated payload
// is ever presented to clamd as a complete stream.
//
// Read failures are wrapped in *SourceError, write failures in *SinkError.
// On any error the zero-length terminator is NOT written; the caller must
// close the connection so clamd cannot treat a partial stream as complete.
func StreamAll(w io.Writer, r io.Reader, chunkSize int, maxBytes int64) (int64, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	if chunkSize > MaxChunkSize {
		chunkSize = MaxChunkSize
	}
	buf := make([]byte, chunkHeaderSize+chunkSize)
	var total int64
	for {
		n, rerr := io.ReadFull(r, buf[chunkHeaderSize:])
		if n > 0 {
			if maxBytes >= 0 && total+int64(n) > maxBytes {
				return total, ErrSizeLimitExceeded
			}
			binary.BigEndian.PutUint32(buf[:chunkHeaderSize], uint32(n))
			if _, werr := w.Write(buf[:chunkHeaderSize+n]); werr != nil {
				return total, &SinkError{Err: werr}
			}
			total += int64(n)
		}
		if rerr != nil {
			if rerr == io.EOF || errors.Is(rerr, io.ErrUnexpectedEOF) {
				break
			}
			return total, &SourceError{Err: rerr}
		}
	}
	binary.BigEndian.PutUint32(buf[:chunkHeaderSize], 0)
	if _, werr := w.Write(buf[:chunkHeaderSize]); werr != nil {
		return total, &SinkError{Err: werr}
	}
	return total, nil
}
