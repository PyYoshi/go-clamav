package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
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
