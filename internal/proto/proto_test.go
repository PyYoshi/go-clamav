package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestEncodeCommand(t *testing.T) {
	got := EncodeCommand("PING")
	want := []byte("zPING\x00")
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeCommand(PING) = %q, want %q", got, want)
	}
}

// chunkFrames decodes the INSTREAM wire format back into payload chunks and
// reports whether a zero-length terminator was present.
func chunkFrames(t *testing.T, wire []byte) (payload []byte, terminated bool) {
	t.Helper()
	for len(wire) > 0 {
		if len(wire) < 4 {
			t.Fatalf("trailing garbage shorter than a chunk header: %v", wire)
		}
		n := binary.BigEndian.Uint32(wire[:4])
		wire = wire[4:]
		if n == 0 {
			if len(wire) != 0 {
				t.Fatalf("data after zero-length terminator: %v", wire)
			}
			return payload, true
		}
		if uint32(len(wire)) < n {
			t.Fatalf("chunk header claims %d bytes, only %d remain", n, len(wire))
		}
		payload = append(payload, wire[:n]...)
		wire = wire[n:]
	}
	return payload, false
}

func TestStreamAll(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		chunkSize int
		maxBytes  int64
	}{
		{"empty input", "", 4, -1},
		{"single partial chunk", "abc", 4, -1},
		{"exact chunk multiple", "abcdefgh", 4, -1},
		{"multiple chunks with remainder", "abcdefghij", 4, -1},
		{"limit exactly met", "abcdefgh", 4, 8},
		{"one byte chunks", "xyz", 1, -1},
		{"defensive chunk size fallback", "hello", 0, -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sink bytes.Buffer
			n, err := StreamAll(&sink, strings.NewReader(tt.input), tt.chunkSize, tt.maxBytes)
			if err != nil {
				t.Fatalf("StreamAll() error = %v", err)
			}
			if n != int64(len(tt.input)) {
				t.Errorf("written = %d, want %d", n, len(tt.input))
			}
			payload, terminated := chunkFrames(t, sink.Bytes())
			if string(payload) != tt.input {
				t.Errorf("payload = %q, want %q", payload, tt.input)
			}
			if !terminated {
				t.Error("zero-length terminator missing")
			}
		})
	}
}

func TestStreamAllWireFormat(t *testing.T) {
	var sink bytes.Buffer
	if _, err := StreamAll(&sink, strings.NewReader("abcdef"), 4, -1); err != nil {
		t.Fatal(err)
	}
	want := []byte("\x00\x00\x00\x04abcd\x00\x00\x00\x02ef\x00\x00\x00\x00")
	if !bytes.Equal(sink.Bytes(), want) {
		t.Errorf("wire = %q, want %q", sink.Bytes(), want)
	}
}

func TestStreamAllSizeLimit(t *testing.T) {
	var sink bytes.Buffer
	n, err := StreamAll(&sink, strings.NewReader("abcdefghi"), 4, 8)
	if !errors.Is(err, ErrSizeLimitExceeded) {
		t.Fatalf("error = %v, want ErrSizeLimitExceeded", err)
	}
	if n != 8 {
		t.Errorf("written = %d, want 8", n)
	}
	// The offending chunk and the terminator must not have been written:
	// clamd must never see a truncated stream presented as complete.
	payload, terminated := chunkFrames(t, sink.Bytes())
	if string(payload) != "abcdefgh" {
		t.Errorf("payload = %q, want %q", payload, "abcdefgh")
	}
	if terminated {
		t.Error("terminator written despite size limit error")
	}
}

func TestStreamAllZeroLimit(t *testing.T) {
	var sink bytes.Buffer
	_, err := StreamAll(&sink, strings.NewReader("a"), 4, 0)
	if !errors.Is(err, ErrSizeLimitExceeded) {
		t.Fatalf("error = %v, want ErrSizeLimitExceeded", err)
	}
	if sink.Len() != 0 {
		t.Errorf("wrote %d bytes, want 0", sink.Len())
	}
}

type failingReader struct{ err error }

func (r *failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestStreamAllSourceError(t *testing.T) {
	boom := errors.New("boom")
	var sink bytes.Buffer
	_, err := StreamAll(&sink, &failingReader{err: boom}, 4, -1)
	var srcErr *SourceError
	if !errors.As(err, &srcErr) {
		t.Fatalf("error = %T(%v), want *SourceError", err, err)
	}
	if !errors.Is(err, boom) {
		t.Errorf("error chain does not contain the source error: %v", err)
	}
	if _, terminated := chunkFrames(t, sink.Bytes()); terminated {
		t.Error("terminator written despite source error")
	}
}

// truncatedReader yields data and then fails with err — the shape of an
// HTTP request body or multipart part cut short by the peer (net/http and
// mime/multipart report that as io.ErrUnexpectedEOF). withData returns the
// error in the same call as the last data, as mime/multipart's part reader
// does; once makes every later call return (0, io.EOF), as net/http's body
// does after reporting the truncation.
type truncatedReader struct {
	data     string
	err      error
	withData bool
	once     bool
	failed   bool
}

func (r *truncatedReader) Read(p []byte) (int, error) {
	if r.failed && r.once {
		return 0, io.EOF
	}
	if r.data == "" {
		r.failed = true
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if r.data == "" && r.withData {
		r.failed = true
		return n, r.err
	}
	return n, nil
}

// TestStreamAllTruncatedSource pins invariant 4 on the source side: a
// reader's own io.ErrUnexpectedEOF reports truncated input and must fail
// the stream, not end it. io.ReadFull synthesizes the same sentinel for a
// short final read, so treating the sentinel as end-of-input used to
// present truncated uploads to clamd as complete streams.
func TestStreamAllTruncatedSource(t *testing.T) {
	shapes := []struct {
		name     string
		data     string
		withData bool
		once     bool
	}{
		{"error after data", "partial", false, false},
		{"error once then EOF", "partial", false, true},
		// The error arrives with the bytes that complete a chunk, then
		// the source reports EOF: io.ReadFull drops an error that comes
		// with a full buffer, which would terminate this stream.
		{"error with data completing a chunk", "abcdefgh", true, true},
	}
	for _, srcErr := range []error{
		io.ErrUnexpectedEOF,
		fmt.Errorf("multipart: %w", io.ErrUnexpectedEOF),
	} {
		for _, s := range shapes {
			t.Run(srcErr.Error()+"/"+s.name, func(t *testing.T) {
				var sink bytes.Buffer
				src := &truncatedReader{data: s.data, err: srcErr, withData: s.withData, once: s.once}
				_, err := StreamAll(&sink, src, 4, -1)
				var se *SourceError
				if !errors.As(err, &se) {
					t.Fatalf("error = %T(%v), want *SourceError", err, err)
				}
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Errorf("error chain does not contain the source error: %v", err)
				}
				if _, terminated := chunkFrames(t, sink.Bytes()); terminated {
					t.Error("terminator written for a truncated source")
				}
			})
		}
	}
}

// TestStreamAllSizeLimitBeatsSourceError: input past the limit is reported
// as oversized even when the source fails in the same chunk — the way
// http.MaxBytesReader errors just past its cap — so callers keep mapping it
// to "too large" rather than to a generic source failure.
func TestStreamAllSizeLimitBeatsSourceError(t *testing.T) {
	var sink bytes.Buffer
	src := &truncatedReader{data: "abcdefghi", err: errors.New("body too large"), withData: true}
	_, err := StreamAll(&sink, src, 4, 8)
	if !errors.Is(err, ErrSizeLimitExceeded) {
		t.Fatalf("error = %v, want ErrSizeLimitExceeded", err)
	}
	if _, terminated := chunkFrames(t, sink.Bytes()); terminated {
		t.Error("terminator written despite size limit error")
	}
}

// stutterReader interleaves empty (0, nil) reads with one-byte reads. Empty
// reads are discouraged by the io.Reader contract but legal, and sporadic
// ones must not end or fail the stream.
type stutterReader struct {
	r     io.Reader
	empty bool
}

func (s *stutterReader) Read(p []byte) (int, error) {
	s.empty = !s.empty
	if s.empty || len(p) == 0 {
		return 0, nil
	}
	return s.r.Read(p[:1])
}

// TestStreamAllReaderShapes: chunks are filled to chunkSize however the
// source splits its reads, and data returned together with io.EOF is
// streamed before the terminator.
func TestStreamAllReaderShapes(t *testing.T) {
	const input = "abcdefghij"
	want := []byte("\x00\x00\x00\x04abcd\x00\x00\x00\x04efgh\x00\x00\x00\x02ij\x00\x00\x00\x00")
	shapes := []struct {
		name string
		wrap func(io.Reader) io.Reader
	}{
		{"plain", func(r io.Reader) io.Reader { return r }},
		{"one byte reads", iotest.OneByteReader},
		{"half reads", iotest.HalfReader},
		{"data with EOF", iotest.DataErrReader},
		{"interleaved empty reads", func(r io.Reader) io.Reader { return &stutterReader{r: r} }},
	}
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			var sink bytes.Buffer
			n, err := StreamAll(&sink, s.wrap(strings.NewReader(input)), 4, -1)
			if err != nil {
				t.Fatalf("StreamAll() error = %v", err)
			}
			if n != int64(len(input)) {
				t.Errorf("written = %d, want %d", n, len(input))
			}
			if !bytes.Equal(sink.Bytes(), want) {
				t.Errorf("wire = %q, want %q", sink.Bytes(), want)
			}
		})
	}
}

// emptyReader returns (0, nil) forever. The call cap bounds the test
// itself: a regression to an unbounded read loop fails instead of hanging
// the suite.
type emptyReader struct{ calls int }

func (r *emptyReader) Read([]byte) (int, error) {
	r.calls++
	if r.calls > 10_000 {
		return 0, errors.New("emptyReader: read loop never gave up")
	}
	return 0, nil
}

func TestStreamAllNoProgress(t *testing.T) {
	var sink bytes.Buffer
	_, err := StreamAll(&sink, &emptyReader{}, 4, -1)
	var se *SourceError
	if !errors.As(err, &se) || !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("error = %T(%v), want *SourceError wrapping io.ErrNoProgress", err, err)
	}
	if sink.Len() != 0 {
		t.Errorf("wrote %d bytes, want 0", sink.Len())
	}
}

// badCountReader violates the io.Reader contract with an impossible count.
type badCountReader struct{ n func(p []byte) int }

func (r badCountReader) Read(p []byte) (int, error) { return r.n(p), nil }

// TestStreamAllInvalidReadCount: a broken source must fail the scan with an
// error, never panic the caller (a security control must fail closed, not
// crash).
func TestStreamAllInvalidReadCount(t *testing.T) {
	counts := []struct {
		name string
		n    func(p []byte) int
	}{
		{"negative", func([]byte) int { return -1 }},
		{"beyond buffer", func(p []byte) int { return len(p) + 1 }},
	}
	for _, c := range counts {
		t.Run(c.name, func(t *testing.T) {
			var sink bytes.Buffer
			_, err := StreamAll(&sink, badCountReader{n: c.n}, 4, -1)
			var se *SourceError
			if !errors.As(err, &se) || !errors.Is(err, errInvalidRead) {
				t.Fatalf("error = %T(%v), want *SourceError wrapping errInvalidRead", err, err)
			}
			if sink.Len() != 0 {
				t.Errorf("wrote %d bytes, want 0", sink.Len())
			}
		})
	}
}

type failingWriter struct {
	failAfter int // bytes accepted before failing
	err       error
	n         int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.n+len(p) > w.failAfter {
		return 0, w.err
	}
	w.n += len(p)
	return len(p), nil
}

func TestStreamAllSinkError(t *testing.T) {
	boom := errors.New("broken pipe")
	_, err := StreamAll(&failingWriter{failAfter: 0, err: boom}, strings.NewReader("abc"), 4, -1)
	var sinkErr *SinkError
	if !errors.As(err, &sinkErr) {
		t.Fatalf("error = %T(%v), want *SinkError", err, err)
	}
	if !errors.Is(err, boom) {
		t.Errorf("error chain does not contain the sink error: %v", err)
	}
}

func TestStreamAllSinkErrorOnTerminator(t *testing.T) {
	// 4-byte header + 3 payload bytes succeed; the 4-byte terminator fails.
	boom := errors.New("broken pipe")
	n, err := StreamAll(&failingWriter{failAfter: 7, err: boom}, strings.NewReader("abc"), 4, -1)
	var sinkErr *SinkError
	if !errors.As(err, &sinkErr) {
		t.Fatalf("error = %T(%v), want *SinkError", err, err)
	}
	if n != 3 {
		t.Errorf("written = %d, want 3", n)
	}
}
