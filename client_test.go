package clamav

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PyYoshi/go-clamav/internal/clamdtest"
	"github.com/PyYoshi/go-clamav/internal/proto"
)

// forEachNetwork runs a subtest against both a unix and a tcp fake.
func forEachNetwork(t *testing.T, fn func(t *testing.T, fake *clamdtest.Fake)) {
	t.Helper()
	for _, network := range []string{"unix", "tcp"} {
		t.Run(network, func(t *testing.T) {
			fn(t, clamdtest.New(t, network))
		})
	}
}

func newClient(t *testing.T, addr string, opts ...Option) *Client {
	t.Helper()
	c, err := New(addr, opts...)
	if err != nil {
		t.Fatalf("New(%q) failed: %v", addr, err)
	}
	return c
}

// assertFailClosed enforces the library-wide contract: any error implies the
// zero ScanResult, which can never read as clean.
func assertFailClosed(t *testing.T, res ScanResult, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if res != (ScanResult{}) {
		t.Fatalf("non-zero ScanResult %+v returned alongside error %v", res, err)
	}
	if res.Clean() {
		t.Fatal("errored scan reports Clean() == true")
	}
}

func TestScanClean(t *testing.T) {
	forEachNetwork(t, func(t *testing.T, fake *clamdtest.Fake) {
		c := newClient(t, fake.Addr)
		res, err := c.Scan(context.Background(), strings.NewReader("hello, world"))
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		if !res.Clean() || res.Infected() || res.Verdict != VerdictClean {
			t.Errorf("result = %+v, want clean", res)
		}
		if res.Raw != "stream: OK" {
			t.Errorf("Raw = %q", res.Raw)
		}
	})
}

func TestScanEmptyInput(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	c := newClient(t, fake.Addr)
	res, err := c.Scan(context.Background(), strings.NewReader(""))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if !res.Clean() {
		t.Errorf("result = %+v, want clean", res)
	}
}

func TestScanInfected(t *testing.T) {
	forEachNetwork(t, func(t *testing.T, fake *clamdtest.Fake) {
		var gotBody atomic.Pointer[[]byte]
		fake.SetHandler(func(req clamdtest.Request) clamdtest.Response {
			body := append([]byte(nil), req.Body...)
			gotBody.Store(&body)
			return clamdtest.Response{Data: []byte("stream: Win.Test.EICAR_HDB-1 FOUND\x00")}
		})
		c := newClient(t, fake.Addr)
		payload := bytes.Repeat([]byte("scan me "), 10000) // > 1 chunk
		res, err := c.Scan(context.Background(), bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		if !res.Infected() || res.Clean() {
			t.Fatalf("result = %+v, want infected", res)
		}
		if res.Signature != "Win.Test.EICAR_HDB-1" {
			t.Errorf("Signature = %q", res.Signature)
		}
		if body := gotBody.Load(); body == nil || !bytes.Equal(*body, payload) {
			t.Error("fake did not receive the exact payload that was streamed")
		}
	})
}

func TestScanInfectedVariants(t *testing.T) {
	tests := []struct {
		name    string
		reply   string
		wantSig string
	}{
		{"multi-word signature", "stream: Some sig with spaces FOUND\x00", "Some sig with spaces"},
		{"unknown prefix still infected", "instream (local): Eicar-Signature FOUND\x00", "Eicar-Signature"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := clamdtest.New(t, "unix")
			fake.SetHandler(clamdtest.RespondWith(tt.reply))
			c := newClient(t, fake.Addr)
			res, err := c.Scan(context.Background(), strings.NewReader("x"))
			if err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			if !res.Infected() || res.Signature != tt.wantSig {
				t.Errorf("result = %+v, want infected with signature %q", res, tt.wantSig)
			}
		})
	}
}

func TestScanClamdError(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	fake.SetHandler(clamdtest.RespondWith("stream: Some engine failure ERROR\x00"))
	c := newClient(t, fake.Addr)
	res, err := c.Scan(context.Background(), strings.NewReader("x"))
	assertFailClosed(t, res, err)
	var clamdErr *ClamdError
	if !errors.As(err, &clamdErr) {
		t.Fatalf("error = %T(%v), want *ClamdError", err, err)
	}
	if errors.Is(err, ErrSizeLimitExceeded) {
		t.Error("generic clamd error must not match ErrSizeLimitExceeded")
	}
	if IsRetryable(err) {
		t.Error("clamd error classified as retryable")
	}
}

func TestScanUnknownResponse(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	fake.SetHandler(clamdtest.RespondWith("wat\x00"))
	c := newClient(t, fake.Addr)
	res, err := c.Scan(context.Background(), strings.NewReader("x"))
	assertFailClosed(t, res, err)
	var protoErr *ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("error = %T(%v), want *ProtocolError", err, err)
	}
	if IsRetryable(err) {
		t.Error("protocol error classified as retryable")
	}
}

func TestScanOversizedResponse(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	fake.SetHandler(clamdtest.RespondWith(strings.Repeat("A", 64<<10) + "\x00"))
	c := newClient(t, fake.Addr)
	res, err := c.Scan(context.Background(), strings.NewReader("x"))
	assertFailClosed(t, res, err)
	var protoErr *ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("error = %T(%v), want *ProtocolError", err, err)
	}
}

func TestScanServerClosesWithoutResponse(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	fake.SetHandler(func(clamdtest.Request) clamdtest.Response {
		return clamdtest.Response{} // no data; fake closes the connection
	})
	c := newClient(t, fake.Addr)
	res, err := c.Scan(context.Background(), strings.NewReader("x"))
	assertFailClosed(t, res, err)
	var connErr *ConnectionError
	if !errors.As(err, &connErr) {
		t.Fatalf("error = %T(%v), want *ConnectionError", err, err)
	}
	if !IsRetryable(err) {
		t.Error("connection error should be retryable")
	}
}

func TestScanClientSizeLimit(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	c := newClient(t, fake.Addr, WithMaxStreamSize(1024))
	res, err := c.Scan(context.Background(), bytes.NewReader(make([]byte, 4096)))
	assertFailClosed(t, res, err)
	if !errors.Is(err, ErrSizeLimitExceeded) {
		t.Fatalf("error = %v, want ErrSizeLimitExceeded", err)
	}
	if !strings.Contains(err.Error(), "client-side") {
		t.Errorf("error message should attribute the limit to the client side: %v", err)
	}
	if IsRetryable(err) {
		t.Error("size limit error classified as retryable")
	}
}

func TestScanBytesSizeLimitSkipsDial(t *testing.T) {
	var dials atomic.Int32
	c := newClient(t, "tcp://127.0.0.1:1", // never reached
		WithMaxStreamSize(8),
		WithDialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("must not dial")
		}))
	res, err := c.ScanBytes(context.Background(), make([]byte, 64))
	assertFailClosed(t, res, err)
	if !errors.Is(err, ErrSizeLimitExceeded) {
		t.Fatalf("error = %v, want ErrSizeLimitExceeded", err)
	}
	if dials.Load() != 0 {
		t.Error("oversized ScanBytes dialed clamd; the limit must be enforced first")
	}
}

func TestScanBytesClean(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	c := newClient(t, fake.Addr)
	res, err := c.ScanBytes(context.Background(), []byte("payload"))
	if err != nil || !res.Clean() {
		t.Fatalf("ScanBytes() = %+v, %v; want clean", res, err)
	}
}

func TestScanFile(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	var gotBody atomic.Pointer[[]byte]
	fake.SetHandler(func(req clamdtest.Request) clamdtest.Response {
		body := append([]byte(nil), req.Body...)
		gotBody.Store(&body)
		return clamdtest.Response{Data: []byte("stream: OK\x00")}
	})
	c := newClient(t, fake.Addr)

	path := filepath.Join(t.TempDir(), "upload.bin")
	content := bytes.Repeat([]byte{0xAB}, 100_000)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := c.ScanFile(context.Background(), path)
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}
	if !res.Clean() {
		t.Errorf("result = %+v, want clean", res)
	}
	if body := gotBody.Load(); body == nil || !bytes.Equal(*body, content) {
		t.Error("fake did not receive the exact file contents")
	}
}

func TestScanFileSizeLimitSkipsDial(t *testing.T) {
	var dials atomic.Int32
	c := newClient(t, "tcp://127.0.0.1:1",
		WithMaxStreamSize(16),
		WithDialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("must not dial")
		}))
	path := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(path, make([]byte, 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := c.ScanFile(context.Background(), path)
	assertFailClosed(t, res, err)
	if !errors.Is(err, ErrSizeLimitExceeded) {
		t.Fatalf("error = %v, want ErrSizeLimitExceeded", err)
	}
	if dials.Load() != 0 {
		t.Error("oversized ScanFile dialed clamd; the limit must be enforced first")
	}
}

func TestScanFileErrors(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	c := newClient(t, fake.Addr)

	t.Run("missing file", func(t *testing.T) {
		res, err := c.ScanFile(context.Background(), filepath.Join(t.TempDir(), "nope"))
		assertFailClosed(t, res, err)
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("error = %v, want fs.ErrNotExist in chain", err)
		}
	})
	t.Run("directory", func(t *testing.T) {
		res, err := c.ScanFile(context.Background(), t.TempDir())
		assertFailClosed(t, res, err)
		if !strings.Contains(err.Error(), "regular file") {
			t.Errorf("error = %v, want regular-file rejection", err)
		}
	})
}

// TestScanServerStreamLimit exercises the write-error recovery path: the
// fake emulates clamd's StreamMaxLength by replying with the size-limit
// ERROR mid-stream and closing the connection. Depending on socket buffer
// sizes the client either observes a write failure and must recover the
// buffered reply, or completes the stream and reads the reply normally —
// both must surface ErrSizeLimitExceeded. Unix only: closing a TCP socket
// with unread data can RST away the reply, which is separately handled as a
// (retryable) connection error.
func TestScanServerStreamLimit(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	fake.SetStreamLimit(1024)
	c := newClient(t, fake.Addr, WithMaxStreamSize(NoSizeLimit))
	res, err := c.Scan(context.Background(), bytes.NewReader(make([]byte, 8<<20)))
	assertFailClosed(t, res, err)
	if !errors.Is(err, ErrSizeLimitExceeded) {
		t.Fatalf("error = %v, want ErrSizeLimitExceeded", err)
	}
	var clamdErr *ClamdError
	if !errors.As(err, &clamdErr) {
		t.Fatalf("error = %v, want *ClamdError in chain (server-side limit)", err)
	}
	if IsRetryable(err) {
		t.Error("server size limit classified as retryable")
	}
}

func TestScanSourceReadError(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	c := newClient(t, fake.Addr)
	boom := errors.New("upload stream broke")
	r := io.MultiReader(strings.NewReader("partial"), &failReader{err: boom})
	res, err := c.Scan(context.Background(), r)
	assertFailClosed(t, res, err)
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want the source error in the chain", err)
	}
	if IsRetryable(err) {
		t.Error("source read error must not be classified retryable (input is consumed)")
	}
}

type failReader struct{ err error }

func (r *failReader) Read([]byte) (int, error) { return 0, r.err }

// TestScanTruncatedSource: a source cut short must fail the scan. net/http
// and mime/multipart report a truncated request body as io.ErrUnexpectedEOF;
// streaming that as a complete INSTREAM would return a verdict for an
// upload the caller never fully received.
func TestScanTruncatedSource(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	var handled atomic.Bool
	fake.SetHandler(func(req clamdtest.Request) clamdtest.Response {
		handled.Store(true)
		return clamdtest.DefaultHandler(req)
	})
	c := newClient(t, fake.Addr)
	r := io.MultiReader(strings.NewReader("partial upload"), &failReader{err: io.ErrUnexpectedEOF})
	res, err := c.Scan(context.Background(), r)
	assertFailClosed(t, res, err)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("error = %v, want the source's io.ErrUnexpectedEOF in the chain", err)
	}
	if IsRetryable(err) {
		t.Error("truncated source classified as retryable (input is consumed)")
	}
	fake.Close() // wait for the connection handler so handled is final
	if handled.Load() {
		t.Error("clamd received a complete INSTREAM for a truncated source")
	}
}

// TestScanSizeLimitBeatsSourceError: http.MaxBytesReader fails in the same
// chunk that crosses the client-side limit when its cap sits just above
// it. The scan must still report ErrSizeLimitExceeded (a 413 for the
// caller), not a generic source failure.
func TestScanSizeLimitBeatsSourceError(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	c := newClient(t, fake.Addr, WithMaxStreamSize(1024))
	body := http.MaxBytesReader(nil, io.NopCloser(bytes.NewReader(make([]byte, 4096))), 1025)
	res, err := c.Scan(context.Background(), body)
	assertFailClosed(t, res, err)
	if !errors.Is(err, ErrSizeLimitExceeded) {
		t.Fatalf("error = %v, want ErrSizeLimitExceeded", err)
	}
}

// cancelingReader cancels the scan during its first Read and then keeps
// delivering one byte per call without ever blocking, like a trickling
// upload. The call cap turns a regression into a failure, not a hang.
type cancelingReader struct {
	cancel context.CancelFunc
	calls  int
}

func (r *cancelingReader) Read(p []byte) (int, error) {
	r.calls++
	if r.calls == 1 {
		r.cancel()
	}
	if r.calls > 1000 {
		return 0, errors.New("source still read long after cancellation")
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = 'x'
	return 1, nil
}

// cancelOnFailReader fails the way a net/http request body does when the
// client disconnects: the server cancels the request context before the
// failing Read returns io.ErrUnexpectedEOF.
type cancelOnFailReader struct{ cancel context.CancelFunc }

func (r *cancelOnFailReader) Read([]byte) (int, error) {
	r.cancel()
	return 0, io.ErrUnexpectedEOF
}

// TestScanSourceErrorBeatsItsOwnCancellation: when the source fails on its
// own, its error is the cause even if ctx is done by the time the scan
// classifies it. Otherwise every truncated or timed-out HTTP upload would
// read as a plain cancellation and lose the cause callers match on.
func TestScanSourceErrorBeatsItsOwnCancellation(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	c := newClient(t, fake.Addr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res, err := c.Scan(ctx, &cancelOnFailReader{cancel: cancel})
	assertFailClosed(t, res, err)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("error = %v, want the source's io.ErrUnexpectedEOF in the chain", err)
	}
	if IsRetryable(err) {
		t.Error("source failure classified as retryable")
	}
}

// TestScanCancelStopsSourceReads: ctx is checked before every Read on the
// source, so a scan cancelled while its source trickles data stops reading
// at once, instead of after filling a whole chunk (32 KiB of one-byte
// reads here) while holding its scan slot and clamd connection.
func TestScanCancelStopsSourceReads(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	c := newClient(t, fake.Addr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := &cancelingReader{cancel: cancel}
	res, err := c.Scan(ctx, src)
	assertFailClosed(t, res, err)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if !strings.Contains(err.Error(), "scan aborted") {
		t.Errorf("error = %q, want the cancellation reported as an aborted scan, not a source failure", err)
	}
	if src.calls != 1 {
		t.Errorf("source read %d times, want 1 (no Read after cancellation)", src.calls)
	}
}

// TestScanUnterminatedReply pins ADR-0007: z-form replies always end with
// a NUL, so a reply that ends at EOF may be cut short and must never yield
// a clean verdict. clamd writes each reply and its NUL together, so this
// marks a non-conforming peer: a non-retryable ProtocolError, as for any
// other reply outside the grammar. A detection still counts: it can only
// reject.
func TestScanUnterminatedReply(t *testing.T) {
	for _, reply := range []string{"stream: OK", "OK", "stream: OK\n"} {
		t.Run(fmt.Sprintf("%q", reply), func(t *testing.T) {
			fake := clamdtest.New(t, "unix")
			fake.SetHandler(clamdtest.RespondWith(reply))
			c := newClient(t, fake.Addr)
			res, err := c.Scan(context.Background(), strings.NewReader("x"))
			assertFailClosed(t, res, err)
			var protoErr *ProtocolError
			if !errors.As(err, &protoErr) {
				t.Fatalf("error = %T(%v), want *ProtocolError", err, err)
			}
			if IsRetryable(err) {
				t.Error("unterminated reply classified as retryable")
			}
		})
	}
	t.Run("detection still counts", func(t *testing.T) {
		fake := clamdtest.New(t, "unix")
		fake.SetHandler(clamdtest.RespondWith("stream: Evil FOUND"))
		c := newClient(t, fake.Addr)
		res, err := c.Scan(context.Background(), strings.NewReader("x"))
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		if !res.Infected() || res.Signature != "Evil" {
			t.Errorf("result = %+v, want infected with signature Evil", res)
		}
	})
}

func TestScanIOTimeout(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	fake.SetHandler(func(clamdtest.Request) clamdtest.Response {
		return clamdtest.Response{Hang: true}
	})
	c := newClient(t, fake.Addr, WithIOTimeout(150*time.Millisecond))
	start := time.Now()
	res, err := c.Scan(context.Background(), strings.NewReader("x"))
	assertFailClosed(t, res, err)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("scan took %v; I/O timeout did not fire", elapsed)
	}
	var connErr *ConnectionError
	if !errors.As(err, &connErr) {
		t.Fatalf("error = %T(%v), want *ConnectionError", err, err)
	}
	if !IsRetryable(err) {
		t.Error("I/O timeout should be retryable")
	}
}

func TestScanContextCancelDuringRead(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	fake.SetHandler(func(clamdtest.Request) clamdtest.Response {
		return clamdtest.Response{Hang: true}
	})
	c := newClient(t, fake.Addr) // default 30s I/O timeout: cancellation must win
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	res, err := c.Scan(ctx, strings.NewReader("x"))
	assertFailClosed(t, res, err)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("cancellation took %v to unblock the scan", elapsed)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled in chain", err)
	}
	if IsRetryable(err) {
		t.Error("deliberate cancellation classified as retryable")
	}
}

func TestScanContextDeadlineDuringWrite(t *testing.T) {
	// A net.Pipe with no reader blocks writes forever; only the context
	// deadline (via the cancel watcher) can unblock the scan.
	c := newClient(t, "tcp://127.0.0.1:1",
		WithDialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
			client, server := net.Pipe()
			t.Cleanup(func() { server.Close() })
			return client, nil
		}))
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	res, err := c.Scan(ctx, strings.NewReader("payload"))
	assertFailClosed(t, res, err)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("deadline took %v to unblock the write", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded in chain", err)
	}
	if !IsRetryable(err) {
		t.Error("deadline expiry should be retryable")
	}
}

// TestScanMultilineReply guards the strict single-line rule: a reply whose
// first line looks clean but that smuggles more content after a newline
// must be a protocol error, never a verdict.
func TestScanMultilineReply(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	fake.SetHandler(clamdtest.RespondWith("stream: OK\nEvil FOUND\x00"))
	c := newClient(t, fake.Addr)
	res, err := c.Scan(context.Background(), strings.NewReader("x"))
	assertFailClosed(t, res, err)
	var protoErr *ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("error = %T(%v), want *ProtocolError", err, err)
	}
}

func TestScanDialTimeout(t *testing.T) {
	c := newClient(t, "tcp://127.0.0.1:1",
		WithDialTimeout(100*time.Millisecond),
		WithDialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
			<-ctx.Done() // never connects; honors the dial-timeout sub-context
			return nil, ctx.Err()
		}))
	start := time.Now()
	res, err := c.Scan(context.Background(), strings.NewReader("x"))
	assertFailClosed(t, res, err)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("dial timeout took %v to fire", elapsed)
	}
	var connErr *ConnectionError
	if !errors.As(err, &connErr) || connErr.Op != "dial" {
		t.Fatalf("error = %T(%v), want *ConnectionError{Op: dial}", err, err)
	}
	if !IsRetryable(err) {
		t.Error("dial timeout should be retryable")
	}
}

func TestScanNilConnFromDialFunc(t *testing.T) {
	c := newClient(t, "tcp://127.0.0.1:1",
		WithDialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, nil // misbehaving dialer: must error, not panic
		}))
	res, err := c.Scan(context.Background(), strings.NewReader("x"))
	assertFailClosed(t, res, err)
	var connErr *ConnectionError
	if !errors.As(err, &connErr) {
		t.Fatalf("error = %T(%v), want *ConnectionError", err, err)
	}
}

func TestScanDialFailure(t *testing.T) {
	c := newClient(t, "unix:///nonexistent/clamd.sock")
	res, err := c.Scan(context.Background(), strings.NewReader("x"))
	assertFailClosed(t, res, err)
	var connErr *ConnectionError
	if !errors.As(err, &connErr) {
		t.Fatalf("error = %T(%v), want *ConnectionError", err, err)
	}
	if connErr.Op != "dial" {
		t.Errorf("Op = %q, want dial", connErr.Op)
	}
	if !IsRetryable(err) {
		t.Error("dial failure should be retryable")
	}
}

func TestScanNilReader(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	c := newClient(t, fake.Addr)
	res, err := c.Scan(context.Background(), nil)
	assertFailClosed(t, res, err)
}

func TestScanConcurrencyLimit(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	var current, peak atomic.Int32
	fake.SetHandler(func(clamdtest.Request) clamdtest.Response {
		n := current.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		current.Add(-1)
		return clamdtest.Response{Data: []byte("stream: OK\x00")}
	})
	c := newClient(t, fake.Addr, WithMaxConcurrentScans(2))

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = c.Scan(context.Background(), strings.NewReader("x"))
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("scan %d failed: %v", i, err)
		}
	}
	if p := peak.Load(); p > 2 {
		t.Errorf("peak concurrent scans = %d, want <= 2", p)
	}
}

func TestScanSlotWaitRespectsContext(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	fake.SetHandler(func(clamdtest.Request) clamdtest.Response {
		time.Sleep(400 * time.Millisecond)
		return clamdtest.Response{Data: []byte("stream: OK\x00")}
	})
	c := newClient(t, fake.Addr, WithMaxConcurrentScans(1))

	started := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		close(started)
		if _, err := c.Scan(context.Background(), strings.NewReader("x")); err != nil {
			t.Errorf("slot-holding scan failed: %v", err)
		}
	}()
	<-started
	time.Sleep(50 * time.Millisecond) // let the first scan claim the slot

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	res, err := c.Scan(ctx, strings.NewReader("y"))
	assertFailClosed(t, res, err)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded while queued", err)
	}
	if !IsRetryable(err) {
		t.Error("queue timeout should be retryable")
	}
	wg.Wait()
}

func TestNewValidation(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	tests := []struct {
		name string
		addr string
		opts []Option
	}{
		{"bad scheme", "ftp://x:1", nil},
		{"zero chunk size", fake.Addr, []Option{WithChunkSize(0)}},
		{"huge chunk size", fake.Addr, []Option{WithChunkSize(1 << 30)}},
		{"zero max stream size", fake.Addr, []Option{WithMaxStreamSize(0)}},
		{"negative max stream size", fake.Addr, []Option{WithMaxStreamSize(-2)}},
		{"negative concurrency", fake.Addr, []Option{WithMaxConcurrentScans(-1)}},
		{"zero dial timeout", fake.Addr, []Option{WithDialTimeout(0)}},
		{"zero io timeout", fake.Addr, []Option{WithIOTimeout(0)}},
		{"nil dial func", fake.Addr, []Option{WithDialFunc(nil)}},
		{"nil option", fake.Addr, []Option{nil}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.addr, tt.opts...); err == nil {
				t.Error("New() accepted invalid configuration")
			}
		})
	}
}

// TestErrAlwaysMeansZeroResult drives the client through every scripted
// failure mode and asserts the fail-closed invariant in one sweep.
func TestErrAlwaysMeansZeroResult(t *testing.T) {
	replies := []string{
		"stream: whatever ERROR\x00",
		"INSTREAM size limit exceeded. ERROR\x00",
		"garbage\x00",
		"", // close without reply
		"\x00",
		"stream: OK", // missing terminator, then EOF — incomplete, so an error (ADR-0007)
	}
	for _, reply := range replies {
		fake := clamdtest.New(t, "unix")
		fake.SetHandler(clamdtest.RespondWith(reply))
		c := newClient(t, fake.Addr)
		res, err := c.Scan(context.Background(), strings.NewReader("x"))
		if err != nil && res != (ScanResult{}) {
			t.Errorf("reply %q: error %v returned with non-zero result %+v", reply, err, res)
		}
		if err == nil && res.Verdict == VerdictUnknown {
			t.Errorf("reply %q: nil error with VerdictUnknown result", reply)
		}
		fake.Close()
	}
}

// The mid-stream tests below script a server that replies while the client
// is still writing INSTREAM chunks (8 MiB payload, reply after 1 KiB), so
// the client's next write fails and recoverStreamError must classify the
// buffered reply. Unix only: closing a TCP socket with unread data can RST
// the buffered reply away, which is separately handled as a (retryable)
// connection error.

// TestScanMidStreamFoundIsDefinitive: a detection is a complete verdict
// even when the stream was never fully sent.
func TestScanMidStreamFoundIsDefinitive(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	fake.SetEarlyReply(1024, "stream: Evil FOUND\x00")
	c := newClient(t, fake.Addr, WithMaxStreamSize(NoSizeLimit))
	res, err := c.Scan(context.Background(), bytes.NewReader(make([]byte, 8<<20)))
	if err != nil {
		t.Fatalf("mid-stream detection must be definitive, got error %v", err)
	}
	if !res.Infected() || res.Signature != "Evil" {
		t.Fatalf("res = %+v, want infected with signature Evil", res)
	}
}

// TestScanMidStreamOKIsProtocolError: an "OK" for a stream the client never
// finished sending is inconsistent; trusting it would be fail-open.
func TestScanMidStreamOKIsProtocolError(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	fake.SetEarlyReply(1024, "stream: OK\x00")
	c := newClient(t, fake.Addr, WithMaxStreamSize(NoSizeLimit))
	res, err := c.Scan(context.Background(), bytes.NewReader(make([]byte, 8<<20)))
	assertFailClosed(t, res, err)
	var protoErr *ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("error = %T(%v), want *ProtocolError", err, err)
	}
	if IsRetryable(err) {
		t.Error("OK-for-unfinished-stream classified as retryable")
	}
}

// TestScanMidStreamGarbageIsConnectionError: an unclassifiable mid-stream
// reply falls through to the transport error — the write failure explains
// more than the garbage does, and connection errors are retryable.
func TestScanMidStreamGarbageIsConnectionError(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	fake.SetEarlyReply(1024, "wat\x00")
	c := newClient(t, fake.Addr, WithMaxStreamSize(NoSizeLimit))
	res, err := c.Scan(context.Background(), bytes.NewReader(make([]byte, 8<<20)))
	assertFailClosed(t, res, err)
	var connErr *ConnectionError
	if !errors.As(err, &connErr) {
		t.Fatalf("error = %T(%v), want *ConnectionError", err, err)
	}
	if !IsRetryable(err) {
		t.Error("mid-stream transport failure must be retryable")
	}
}

// TestScanReplyAtReadLimitBoundary pins the reply-read bound through the
// client: exactly proto.MaxLineResponse bytes of content are accepted, one
// byte more is a protocol violation.
func TestScanReplyAtReadLimitBoundary(t *testing.T) {
	mkReply := func(n int) string {
		const prefix, suffix = "stream: ", " FOUND"
		body := prefix + strings.Repeat("A", n-len(prefix)-len(suffix)) + suffix
		if len(body) != n {
			t.Fatalf("bad reply construction: len = %d, want %d", len(body), n)
		}
		return body + "\x00"
	}
	t.Run("at limit", func(t *testing.T) {
		fake := clamdtest.New(t, "unix")
		fake.SetHandler(clamdtest.RespondWith(mkReply(proto.MaxLineResponse)))
		c := newClient(t, fake.Addr)
		res, err := c.Scan(context.Background(), strings.NewReader("x"))
		if err != nil || !res.Infected() {
			t.Fatalf("reply of exactly %d bytes rejected: %+v, %v", proto.MaxLineResponse, res, err)
		}
		if len(res.Raw) != proto.MaxLineResponse {
			t.Errorf("len(Raw) = %d, want %d", len(res.Raw), proto.MaxLineResponse)
		}
	})
	t.Run("one over", func(t *testing.T) {
		fake := clamdtest.New(t, "unix")
		fake.SetHandler(clamdtest.RespondWith(mkReply(proto.MaxLineResponse + 1)))
		c := newClient(t, fake.Addr)
		res, err := c.Scan(context.Background(), strings.NewReader("x"))
		assertFailClosed(t, res, err)
		var protoErr *ProtocolError
		if !errors.As(err, &protoErr) {
			t.Fatalf("error = %T(%v), want *ProtocolError", err, err)
		}
	})
}

// TestScanBytesSizeLimitBoundary pins the client-side limit off-by-one:
// one byte over is rejected before any dial, exactly at the limit proceeds
// to the (failing) dial.
func TestScanBytesSizeLimitBoundary(t *testing.T) {
	var dials atomic.Int32
	c := newClient(t, "tcp://127.0.0.1:1", // never reached
		WithMaxStreamSize(64),
		WithDialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("dial refused by test")
		}))
	res, err := c.ScanBytes(context.Background(), make([]byte, 65))
	assertFailClosed(t, res, err)
	if !errors.Is(err, ErrSizeLimitExceeded) {
		t.Fatalf("error = %v, want ErrSizeLimitExceeded", err)
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("oversized input dialed %d times; the limit must reject first", n)
	}
	res, err = c.ScanBytes(context.Background(), make([]byte, 64))
	assertFailClosed(t, res, err)
	if errors.Is(err, ErrSizeLimitExceeded) {
		t.Fatalf("error = %v; input exactly at the limit must not be size-rejected", err)
	}
	var connErr *ConnectionError
	if !errors.As(err, &connErr) {
		t.Fatalf("error = %T(%v), want *ConnectionError from the dial", err, err)
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("at-limit input dialed %d times, want 1", n)
	}
}

// TestScanSlowDripReply pins the documented no-progress deadline semantics
// (SECURITY.md): a reply dripped one byte per interval makes progress on
// every read, so it must complete even though the total reply time exceeds
// the I/O timeout — bounding the total is the caller's context's job.
func TestScanSlowDripReply(t *testing.T) {
	const (
		drip = 50 * time.Millisecond
		// 10x the drip interval, so a single step stalling on a loaded
		// runner cannot trip the deadline; the 11-byte reply still takes
		// ~550ms and clears the assertion below.
		ioTimeout = 500 * time.Millisecond
	)
	fake := clamdtest.New(t, "unix")
	fake.SetHandler(func(clamdtest.Request) clamdtest.Response {
		return clamdtest.Response{Data: []byte("stream: OK\x00"), DripInterval: drip}
	})
	c := newClient(t, fake.Addr, WithIOTimeout(ioTimeout))
	start := time.Now()
	res, err := c.Scan(context.Background(), strings.NewReader("x"))
	if err != nil || !res.Clean() {
		t.Fatalf("dripped reply failed: %+v, %v", res, err)
	}
	if elapsed := time.Since(start); elapsed < ioTimeout {
		t.Fatalf("scan finished in %v; the reply cannot have been dripped past the I/O timeout", elapsed)
	}
}
