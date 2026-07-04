// Package clamdtest provides a scriptable in-process fake clamd server for
// unit tests. It speaks just enough of the clamd wire protocol to exercise
// the client — z/n command framing and INSTREAM chunk decoding — over both
// unix and tcp listeners, and lets tests script arbitrary (mis)behavior.
package clamdtest

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// connSafetyDeadline bounds every fake connection so a buggy test can never
// hang the suite.
const connSafetyDeadline = 30 * time.Second

// maxFakeChunk caps a single decoded chunk so a broken client cannot make
// the fake allocate unbounded memory.
const maxFakeChunk = 64 << 20

// Request is one decoded client command.
type Request struct {
	// Command is the command name with the z/n framing prefix stripped,
	// e.g. "PING" or "INSTREAM".
	Command string
	// Body is the decoded INSTREAM payload (nil for other commands).
	Body []byte
}

// Response scripts the fake's reaction to a Request. The connection is
// always closed after the response is handled, mimicking clamd ending the
// session after a non-IDSESSION command.
type Response struct {
	// Data is written verbatim; include the trailing NUL yourself.
	Data []byte
	// Delay postpones writing Data (for timeout tests).
	Delay time.Duration
	// Hang, if set, never writes anything and holds the connection open
	// until the fake shuts down (for I/O timeout tests).
	Hang bool
}

// Handler produces the scripted response for one request.
type Handler func(req Request) Response

// Fake is an in-process fake clamd listening on a real socket.
type Fake struct {
	// Addr is scheme-prefixed and can be passed directly to clamav.New.
	Addr string

	ln          net.Listener
	streamLimit atomic.Int64
	mu          sync.Mutex
	handler     Handler
	done        chan struct{}
	closeOnce   sync.Once
	wg          sync.WaitGroup
}

// New starts a fake clamd on the given network ("unix" or "tcp") and
// registers cleanup with t. The default handler behaves like a healthy
// clamd that finds nothing.
func New(t *testing.T, network string) *Fake {
	t.Helper()
	var ln net.Listener
	var addr string
	var lc net.ListenConfig
	switch network {
	case "unix":
		// A dedicated short temp dir keeps the socket path well under the
		// ~108 byte sun_path limit even when t.TempDir() would be long.
		dir, err := os.MkdirTemp("", "clamdtest")
		if err != nil {
			t.Fatalf("clamdtest: creating socket dir: %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		sock := filepath.Join(dir, "clamd.sock")
		ln, err = lc.Listen(context.Background(), "unix", sock)
		if err != nil {
			t.Fatalf("clamdtest: listening on %s: %v", sock, err)
		}
		addr = "unix://" + sock
	case "tcp":
		var err error
		ln, err = lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("clamdtest: listening on tcp: %v", err)
		}
		addr = "tcp://" + ln.Addr().String()
	default:
		t.Fatalf("clamdtest: unsupported network %q", network)
	}
	f := &Fake{
		Addr:    addr,
		ln:      ln,
		handler: DefaultHandler,
		done:    make(chan struct{}),
	}
	f.wg.Add(1)
	go f.serve()
	t.Cleanup(f.Close)
	return f
}

// SetHandler replaces the scripted handler.
func (f *Fake) SetHandler(h Handler) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handler = h
}

// SetStreamLimit makes the fake emulate clamd's StreamMaxLength: once an
// INSTREAM payload exceeds n bytes, it replies "INSTREAM size limit
// exceeded. ERROR" and closes the connection without draining the rest of
// the stream. 0 disables the emulation.
func (f *Fake) SetStreamLimit(n int64) { f.streamLimit.Store(n) }

// Close shuts the fake down and waits for connection goroutines to finish.
// It is idempotent and also registered via t.Cleanup.
func (f *Fake) Close() {
	f.closeOnce.Do(func() {
		close(f.done)
		_ = f.ln.Close()
		f.wg.Wait()
	})
}

func (f *Fake) getHandler() Handler {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.handler
}

func (f *Fake) serve() {
	defer f.wg.Done()
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return // listener closed
		}
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			defer conn.Close()
			f.handleConn(conn)
		}()
	}
}

func (f *Fake) handleConn(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(connSafetyDeadline))
	br := bufio.NewReader(conn)
	cmd, err := readCommand(br)
	if err != nil {
		return
	}
	req := Request{Command: cmd}
	if cmd == "INSTREAM" {
		body, ok := f.readChunks(conn, br)
		if !ok {
			return
		}
		req.Body = body
	}
	resp := f.getHandler()(req)
	if resp.Hang {
		<-f.done
		return
	}
	if resp.Delay > 0 {
		select {
		case <-time.After(resp.Delay):
		case <-f.done:
			return
		}
	}
	if len(resp.Data) > 0 {
		_, _ = conn.Write(resp.Data)
	}
}

func readCommand(br *bufio.Reader) (string, error) {
	var buf []byte
	for {
		b, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		if b == 0 || b == '\n' {
			break
		}
		if len(buf) > 128 {
			return "", errors.New("command too long")
		}
		buf = append(buf, b)
	}
	cmd := strings.TrimSpace(string(buf))
	if len(cmd) > 1 && (cmd[0] == 'z' || cmd[0] == 'n') {
		cmd = cmd[1:]
	}
	return cmd, nil
}

// readChunks decodes INSTREAM framing until the zero-length terminator.
// ok == false means the connection should be dropped without invoking the
// handler (stream-limit emulation or a client-side abort).
func (f *Fake) readChunks(conn net.Conn, br *bufio.Reader) (body []byte, ok bool) {
	limit := f.streamLimit.Load()
	hdr := make([]byte, 4)
	for {
		if _, err := io.ReadFull(br, hdr); err != nil {
			return nil, false
		}
		n := binary.BigEndian.Uint32(hdr)
		if n == 0 {
			return body, true
		}
		if n > maxFakeChunk {
			return nil, false
		}
		chunk := make([]byte, n)
		if _, err := io.ReadFull(br, chunk); err != nil {
			return nil, false
		}
		body = append(body, chunk...)
		if limit > 0 && int64(len(body)) > limit {
			// Mimic clamd: reply, then close (via the caller's defer)
			// without reading the rest of the stream. The client's next
			// write fails and it must recover this reply.
			_, _ = conn.Write([]byte("INSTREAM size limit exceeded. ERROR\x00"))
			return nil, false
		}
	}
}

// DefaultHandler mimics a healthy clamd that finds nothing.
func DefaultHandler(req Request) Response {
	switch req.Command {
	case "PING":
		return Response{Data: []byte("PONG\x00")}
	case "VERSION":
		return Response{Data: []byte("ClamAV 1.4.3/27700/Wed Jul  1 08:32:03 2026\x00")}
	case "RELOAD":
		return Response{Data: []byte("RELOADING\x00")}
	case "STATS":
		return Response{Data: []byte("POOLS: 1\n\nSTATE: VALID PRIMARY\nTHREADS: live 1  idle 0 max 10 idle-timeout 30\nQUEUE: 0 items\nEND\x00")}
	case "INSTREAM":
		return Response{Data: []byte("stream: OK\x00")}
	default:
		return Response{Data: []byte("UNKNOWN COMMAND\x00")}
	}
}

// RespondWith returns a handler that answers every request with the given
// raw bytes (remember the trailing NUL).
func RespondWith(raw string) Handler {
	return func(Request) Response { return Response{Data: []byte(raw)} }
}
