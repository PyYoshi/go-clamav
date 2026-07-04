package clamav

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/PyYoshi/go-clamav/internal/proto"
)

// Client is a clamd client. It is safe for concurrent use by multiple
// goroutines: configuration is immutable after New and every command runs
// on its own connection (clamd closes the connection after each
// non-session command anyway).
type Client struct {
	network string
	target  string
	cfg     config
	sem     chan struct{} // scan concurrency limiter; nil = unlimited
}

// New creates a Client for the clamd instance at addr and validates the
// configuration. addr must use an explicit scheme:
//
//	unix:///run/clamav/clamd.sock
//	tcp://127.0.0.1:3310
//
// No connection is made yet; use Ping to probe reachability.
//
// The address is part of the security configuration: it must come from
// deployment configuration, never from request or user input, and TCP
// should only point at loopback or an isolated private network (the clamd
// protocol is unauthenticated cleartext).
func New(addr string, opts ...Option) (*Client, error) {
	network, target, err := parseAddress(addr)
	if err != nil {
		return nil, err
	}
	cfg := defaultConfig()
	for _, opt := range opts {
		if opt == nil {
			return nil, errors.New("clamav: nil Option")
		}
		opt(&cfg)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	c := &Client{network: network, target: target, cfg: cfg}
	if cfg.maxConcurrentScans > 0 {
		c.sem = make(chan struct{}, cfg.maxConcurrentScans)
	}
	return c, nil
}

// Scan streams r to clamd with the INSTREAM command and returns the verdict.
//
// Fail-closed contract: when err != nil the returned ScanResult is the zero
// value (Verdict == VerdictUnknown) and the data MUST NOT be treated as
// clean. A VerdictInfected result is a successful scan, not an error.
//
// r is consumed exactly once and is not replayed on failure; see IsRetryable
// for which errors are worth retrying with a fresh reader.
func (c *Client) Scan(ctx context.Context, r io.Reader) (ScanResult, error) {
	if r == nil {
		return ScanResult{}, errors.New("clamav: nil reader")
	}
	if err := c.acquireScanSlot(ctx); err != nil {
		return ScanResult{}, err
	}
	defer c.releaseScanSlot()
	return c.scanStream(ctx, r)
}

// ScanBytes scans an in-memory payload. See Scan for the fail-closed
// contract.
func (c *Client) ScanBytes(ctx context.Context, data []byte) (ScanResult, error) {
	if c.cfg.maxStreamSize != NoSizeLimit && int64(len(data)) > c.cfg.maxStreamSize {
		return ScanResult{}, fmt.Errorf("%w: input is %d bytes, client-side limit is %d (WithMaxStreamSize)",
			ErrSizeLimitExceeded, len(data), c.cfg.maxStreamSize)
	}
	return c.Scan(ctx, bytes.NewReader(data))
}

// ScanFile opens path locally and streams its contents to clamd. clamd
// never sees the path and needs no access to the file (the path-based SCAN
// command is deliberately not used: it would require a shared filesystem
// and reintroduce time-of-check/time-of-use concerns).
//
// Files larger than the client-side limit fail with ErrSizeLimitExceeded
// before any connection is made. Only regular files are accepted. See Scan
// for the fail-closed contract.
func (c *Client) ScanFile(ctx context.Context, path string) (ScanResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return ScanResult{}, fmt.Errorf("clamav: opening scan target: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return ScanResult{}, fmt.Errorf("clamav: stat scan target: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return ScanResult{}, fmt.Errorf("clamav: scan target %s is not a regular file (mode %v)", path, fi.Mode())
	}
	if c.cfg.maxStreamSize != NoSizeLimit && fi.Size() > c.cfg.maxStreamSize {
		return ScanResult{}, fmt.Errorf("%w: file is %d bytes, client-side limit is %d (WithMaxStreamSize)",
			ErrSizeLimitExceeded, fi.Size(), c.cfg.maxStreamSize)
	}
	return c.Scan(ctx, f)
}

// acquireScanSlot blocks until a concurrency slot is free or ctx is done.
// Failing the scan when the context expires while queued is intentional:
// under overload the caller gets a retryable error instead of an unbounded
// queue (fail-closed, bounded resources).
func (c *Client) acquireScanSlot(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("clamav: %w", err)
	}
	if c.sem == nil {
		return nil
	}
	select {
	case c.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("clamav: waiting for scan slot: %w", ctx.Err())
	}
}

func (c *Client) releaseScanSlot() {
	if c.sem != nil {
		<-c.sem
	}
}

func (c *Client) scanStream(ctx context.Context, r io.Reader) (ScanResult, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return ScanResult{}, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(abortDeadline) })
	defer stop()

	dc := &deadlineConn{conn: conn, ctx: ctx, ioTimeout: c.cfg.ioTimeout}
	br := bufio.NewReader(dc)

	if _, err := dc.Write(proto.EncodeCommand("INSTREAM")); err != nil {
		return ScanResult{}, wrapIOErr(ctx, "write", err)
	}
	if _, streamErr := proto.StreamAll(dc, r, c.cfg.chunkSize, c.cfg.maxStreamSize); streamErr != nil {
		return c.recoverStreamError(ctx, dc, br, streamErr)
	}
	line, err := proto.ReadLine(br, proto.MaxLineResponse)
	if err != nil {
		return ScanResult{}, wrapReadErr(ctx, "INSTREAM", err)
	}
	return resultFromLine(line)
}

// recoverStreamError classifies a failure that happened while streaming
// chunks to clamd. The connection is in an indeterminate state and is
// always discarded by the caller; no terminator chunk has been written, so
// clamd can never mistake the partial payload for a complete stream.
func (c *Client) recoverStreamError(ctx context.Context, dc *deadlineConn, br *bufio.Reader, streamErr error) (ScanResult, error) {
	// Client-side size limit: deterministic local decision, nothing was
	// promised to clamd.
	if errors.Is(streamErr, proto.ErrSizeLimitExceeded) {
		return ScanResult{}, fmt.Errorf("%w: input exceeds client-side limit of %d bytes (WithMaxStreamSize)",
			ErrSizeLimitExceeded, c.cfg.maxStreamSize)
	}
	// The caller's reader failed; clamd is not involved.
	var srcErr *proto.SourceError
	if errors.As(streamErr, &srcErr) {
		return ScanResult{}, fmt.Errorf("clamav: reading scan source: %w", srcErr.Err)
	}
	// Write failure. Context errors take priority: a cancelled scan must
	// never be misreported as a clamd-side condition.
	if ctxErr := ctxError(ctx); ctxErr != nil {
		return ScanResult{}, fmt.Errorf("clamav: scan aborted: %w", ctxErr)
	}
	// clamd may have replied (typically "INSTREAM size limit exceeded.
	// ERROR") and closed the connection, which is what broke our writes.
	// That reply is far more actionable than a raw broken-pipe error, so
	// try to collect it — briefly: if a reply exists it is already in
	// flight.
	dc.ioTimeout = min(dc.ioTimeout, 2*time.Second)
	if line, rerr := proto.ReadLine(br, proto.MaxLineResponse); rerr == nil {
		switch resp := proto.ParseScanResponse(line); resp.Outcome {
		case proto.OutcomeError:
			return ScanResult{}, clamdErrorFrom(resp)
		case proto.OutcomeInfected:
			// A detection is definitive even if streaming was cut short.
			return ScanResult{Verdict: VerdictInfected, Signature: resp.Signature, Raw: line}, nil
		case proto.OutcomeClean:
			// "OK" for a stream we never finished sending is inconsistent;
			// trusting it would be fail-open.
			return ScanResult{}, &ProtocolError{Command: "INSTREAM", Response: line}
		}
	}
	var sinkErr *proto.SinkError
	if errors.As(streamErr, &sinkErr) {
		return ScanResult{}, wrapIOErr(ctx, "write", sinkErr.Err)
	}
	return ScanResult{}, wrapIOErr(ctx, "write", streamErr)
}

// resultFromLine maps a parsed verdict line to the public API. Unknown
// replies are protocol errors, never verdicts.
func resultFromLine(line string) (ScanResult, error) {
	switch resp := proto.ParseScanResponse(line); resp.Outcome {
	case proto.OutcomeClean:
		return ScanResult{Verdict: VerdictClean, Raw: line}, nil
	case proto.OutcomeInfected:
		return ScanResult{Verdict: VerdictInfected, Signature: resp.Signature, Raw: line}, nil
	case proto.OutcomeError:
		return ScanResult{}, clamdErrorFrom(resp)
	default:
		return ScanResult{}, &ProtocolError{Command: "INSTREAM", Response: line}
	}
}

// clamdErrorFrom converts an ERROR reply into the public error shape. Size
// limit errors additionally match ErrSizeLimitExceeded via errors.Is.
func clamdErrorFrom(resp proto.ScanResponse) error {
	cerr := &ClamdError{Message: resp.Message}
	if resp.SizeLimit {
		return fmt.Errorf("%w: %w (clamd StreamMaxLength)", ErrSizeLimitExceeded, cerr)
	}
	return cerr
}

// ctxError reports the context's failure state. Unlike ctx.Err() alone it
// also treats an already-passed deadline as expiry: the connection deadline
// is derived from the context deadline, so their timers can fire in either
// order — an I/O timeout at the context's deadline is the context's doing
// and must be reported as such, not as a transport failure.
func ctxError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok && !time.Now().Before(dl) {
		return context.DeadlineExceeded
	}
	return nil
}

// wrapIOErr maps a transport failure to the public error shape, giving
// context errors priority so cancellations are reported as such.
func wrapIOErr(ctx context.Context, op string, err error) error {
	if ctxErr := ctxError(ctx); ctxErr != nil {
		return fmt.Errorf("clamav: %s: %w", op, ctxErr)
	}
	return &ConnectionError{Op: op, Err: err}
}

// wrapReadErr maps reply-read failures. An oversized reply is a protocol
// violation by the server, not a transport failure, and must not be
// classified as retryable.
func wrapReadErr(ctx context.Context, command string, err error) error {
	if ctxErr := ctxError(ctx); ctxErr != nil {
		return fmt.Errorf("clamav: read: %w", ctxErr)
	}
	if errors.Is(err, proto.ErrResponseTooLarge) {
		return &ProtocolError{Command: command, Response: "(reply exceeds read limit)"}
	}
	return &ConnectionError{Op: "read", Err: err}
}
