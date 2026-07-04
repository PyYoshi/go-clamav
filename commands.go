package clamav

import (
	"bufio"
	"context"

	"github.com/PyYoshi/go-clamav/internal/proto"
)

// command dials, sends a single z-format command, and reads the reply
// (a single line, or a NUL-terminated block for multi-line replies).
func (c *Client) command(ctx context.Context, name string, block bool) (string, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(abortDeadline) })
	defer stop()

	dc := &deadlineConn{conn: conn, ctx: ctx, ioTimeout: c.cfg.ioTimeout}
	br := bufio.NewReader(dc)

	if _, werr := dc.Write(proto.EncodeCommand(name)); werr != nil {
		return "", wrapWriteErr(ctx, werr)
	}
	var reply string
	var rerr error
	if block {
		reply, rerr = proto.ReadBlock(br, proto.MaxBlockResponse)
	} else {
		reply, rerr = proto.ReadLine(br, proto.MaxLineResponse)
	}
	if rerr != nil {
		return "", wrapReadErr(ctx, name, rerr)
	}
	return reply, nil
}

// expectReply validates a fixed-reply admin command. ERROR replies map to
// ClamdError, anything else unexpected to ProtocolError.
func expectReply(command, reply, want string) error {
	if reply == want {
		return nil
	}
	if resp := proto.ParseScanResponse(reply); resp.Outcome == proto.OutcomeError {
		return clamdErrorFrom(resp)
	}
	return &ProtocolError{Command: command, Response: reply}
}

// Ping checks that clamd is reachable and answering. It is suitable as a
// readiness/health probe. Any reply other than PONG is an error.
func (c *Client) Ping(ctx context.Context) error {
	reply, err := c.command(ctx, "PING", false)
	if err != nil {
		return err
	}
	return expectReply("PING", reply, "PONG")
}

// Version returns the clamd version line, e.g.
//
//	ClamAV 1.4.3/27700/Wed Jul  1 08:32:03 2026
//
// The second and third fields are the signature database version and its
// publication date — useful for monitoring signature freshness.
func (c *Client) Version(ctx context.Context) (string, error) {
	reply, err := c.command(ctx, "VERSION", false)
	if err != nil {
		return "", err
	}
	if resp := proto.ParseScanResponse(reply); resp.Outcome == proto.OutcomeError {
		return "", clamdErrorFrom(resp)
	}
	if reply == "" {
		return "", &ProtocolError{Command: "VERSION", Response: reply}
	}
	return reply, nil
}

// Stats returns clamd's multi-line STATS report (thread pool and queue
// state), for operational monitoring. The format is not stable across
// clamd versions; treat it as diagnostic text.
func (c *Client) Stats(ctx context.Context) (string, error) {
	reply, err := c.command(ctx, "STATS", true)
	if err != nil {
		return "", err
	}
	if resp := proto.ParseScanResponse(reply); resp.Outcome == proto.OutcomeError {
		return "", clamdErrorFrom(resp)
	}
	if reply == "" {
		return "", &ProtocolError{Command: "STATS", Response: reply}
	}
	return reply, nil
}

// Reload asks clamd to reload its signature databases.
//
// This is an administrative operation: signature updates are normally
// driven by freshclam on the clamd side, and a reload briefly increases
// clamd's memory and latency. Do not call it from a scanning code path.
func (c *Client) Reload(ctx context.Context) error {
	reply, err := c.command(ctx, "RELOAD", false)
	if err != nil {
		return err
	}
	return expectReply("RELOAD", reply, "RELOADING")
}
