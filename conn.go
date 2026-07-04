package clamav

import (
	"context"
	"fmt"
	"net"
	"time"
)

// abortDeadline is set on a connection to force any pending or future I/O
// to fail immediately (used when the context is done).
var abortDeadline = time.Unix(1, 0)

// deadlineConn wraps a net.Conn so that every Read/Write first refreshes the
// connection deadline to min(now+ioTimeout, context deadline) and observes
// context cancellation. Callers additionally register a context.AfterFunc
// that slams the deadline shut on cancellation, so blocked I/O unblocks
// promptly instead of waiting for the next operation.
type deadlineConn struct {
	conn      net.Conn
	ctx       context.Context
	ioTimeout time.Duration
}

func (d *deadlineConn) refresh() error {
	if err := d.ctx.Err(); err != nil {
		return err
	}
	t := time.Now().Add(d.ioTimeout)
	if dl, ok := d.ctx.Deadline(); ok && dl.Before(t) {
		t = dl
	}
	if err := d.conn.SetDeadline(t); err != nil {
		return err
	}
	// Close the race with the cancel watcher: if the context was cancelled
	// between the check above and SetDeadline, the watcher's abort deadline
	// may have just been overwritten — reinstate it.
	if err := d.ctx.Err(); err != nil {
		d.conn.SetDeadline(abortDeadline)
		return err
	}
	return nil
}

func (d *deadlineConn) Read(p []byte) (int, error) {
	if err := d.refresh(); err != nil {
		return 0, err
	}
	return d.conn.Read(p)
}

func (d *deadlineConn) Write(p []byte) (int, error) {
	if err := d.refresh(); err != nil {
		return 0, err
	}
	return d.conn.Write(p)
}

// dial establishes a fresh connection for a single command, honoring the
// configured dial timeout and the caller's context.
func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	dctx := ctx
	if c.cfg.dialTimeout > 0 {
		var cancel context.CancelFunc
		dctx, cancel = context.WithTimeout(ctx, c.cfg.dialTimeout)
		defer cancel()
	}
	conn, err := c.cfg.dialFunc(dctx, c.network, c.target)
	if err != nil {
		// Context errors take priority so a cancelled call is reported as
		// such, not as a transport failure. The dial-timeout sub-context is
		// deliberately not consulted: its expiry is a transport condition.
		if ctxErr := ctxError(ctx); ctxErr != nil {
			return nil, fmt.Errorf("clamav: dial: %w", ctxErr)
		}
		return nil, &ConnectionError{Op: "dial", Err: err}
	}
	return conn, nil
}
