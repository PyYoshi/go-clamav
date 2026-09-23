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

	// maxConsecutiveEmptyReads bounds how many (0, nil) reads in a row the
	// source may return before StreamAll gives up with io.ErrNoProgress,
	// mirroring bufio.Reader.
	maxConsecutiveEmptyReads = 100
)

// ErrSizeLimitExceeded is returned by StreamAll when the source would exceed
// the configured byte limit. The chunk that would cross the limit is not
// written to the sink.
var ErrSizeLimitExceeded = errors.New("stream size limit exceeded")

// errInvalidRead reports a source that returned a byte count outside
// [0, len(p)], violating the io.Reader contract.
var errInvalidRead = errors.New("source returned an invalid read count")

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
// Only io.EOF from the source ends the stream. Any other read failure —
// including a source's own io.ErrUnexpectedEOF, which is how net/http and
// mime/multipart report a truncated body — is wrapped in *SourceError, as
// are sources that stop making progress or return impossible counts. Write
// failures are wrapped in *SinkError. On any error the zero-length
// terminator is NOT written; the caller must close the connection so clamd
// cannot treat a partial stream as complete.
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
		n, eof, rerr := fill(r, buf[chunkHeaderSize:])
		// The size limit is checked first, so input that exceeds it is
		// reported as oversized even when the source also failed (e.g.
		// http.MaxBytesReader erroring just past the limit).
		if maxBytes >= 0 && total+int64(n) > maxBytes {
			return total, ErrSizeLimitExceeded
		}
		if rerr != nil {
			// The input is incomplete: sending the bytes already buffered
			// would only waste bandwidth on a stream that is never
			// terminated.
			return total, &SourceError{Err: rerr}
		}
		if n > 0 {
			// #nosec G115 -- n <= chunkSize <= MaxChunkSize (16 MiB), cannot overflow uint32
			binary.BigEndian.PutUint32(buf[:chunkHeaderSize], uint32(n))
			if wn, werr := w.Write(buf[:chunkHeaderSize+n]); werr != nil {
				return total, &SinkError{Err: werr}
			} else if wn != chunkHeaderSize+n {
				return total, &SinkError{Err: io.ErrShortWrite}
			}
			total += int64(n)
		}
		if eof {
			break
		}
	}
	binary.BigEndian.PutUint32(buf[:chunkHeaderSize], 0)
	if wn, werr := w.Write(buf[:chunkHeaderSize]); werr != nil {
		return total, &SinkError{Err: werr}
	} else if wn != chunkHeaderSize {
		return total, &SinkError{Err: io.ErrShortWrite}
	}
	return total, nil
}

// fill reads from r until buf is full or r reports io.EOF. It replaces
// io.ReadFull, whose io.ErrUnexpectedEOF for a short final read is
// indistinguishable from the same sentinel returned by the source itself
// for truncated input: here only io.EOF ends the input, and every other
// error is returned as-is. A source that keeps returning (0, nil) fails
// with io.ErrNoProgress instead of spinning forever, and a count outside
// [0, len(p)] fails with errInvalidRead instead of panicking.
func fill(r io.Reader, buf []byte) (n int, eof bool, err error) {
	empty := 0
	for n < len(buf) {
		nn, rerr := r.Read(buf[n:])
		if nn < 0 || nn > len(buf)-n {
			return n, false, errInvalidRead
		}
		n += nn
		switch {
		case rerr == io.EOF:
			return n, true, nil
		case rerr != nil:
			return n, false, rerr
		case nn > 0:
			empty = 0
		default:
			empty++
			if empty >= maxConsecutiveEmptyReads {
				return n, false, io.ErrNoProgress
			}
		}
	}
	return n, false, nil
}
