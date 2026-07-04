package clamav

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/PyYoshi/go-clamav/internal/proto"
)

// Defaults applied by New. All of them can be overridden with Options.
const (
	// DefaultDialTimeout bounds connection establishment.
	DefaultDialTimeout = 10 * time.Second
	// DefaultIOTimeout bounds each individual read/write operation, i.e.
	// the maximum time the connection may make no progress at all. It is
	// not a whole-scan timeout; bound the total scan with the context.
	DefaultIOTimeout = 30 * time.Second
	// DefaultChunkSize is the INSTREAM chunk payload size.
	DefaultChunkSize = 32 << 10 // 32 KiB
	// DefaultMaxStreamSize is the client-side payload limit. It matches
	// clamd's historical StreamMaxLength default (25 MiB). Configure
	// WithMaxStreamSize to the StreamMaxLength of your clamd deployment.
	DefaultMaxStreamSize int64 = 25 << 20 // 25 MiB
)

// NoSizeLimit disables the client-side stream size limit when passed to
// WithMaxStreamSize. clamd's own StreamMaxLength still applies. Disabling
// the client-side limit is discouraged: it allows a single oversized upload
// to consume bandwidth and clamd resources before being rejected.
const NoSizeLimit int64 = -1

// DialFunc establishes the transport connection. network is "unix" or "tcp"
// as derived from the address passed to New.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Option configures a Client at construction time. Configuration is
// validated and then immutable, which is what makes Client goroutine-safe.
type Option func(*config)

type config struct {
	dialTimeout        time.Duration
	ioTimeout          time.Duration
	chunkSize          int
	maxStreamSize      int64
	maxConcurrentScans int
	dialFunc           DialFunc
}

func defaultConfig() config {
	return config{
		dialTimeout:   DefaultDialTimeout,
		ioTimeout:     DefaultIOTimeout,
		chunkSize:     DefaultChunkSize,
		maxStreamSize: DefaultMaxStreamSize,
		dialFunc:      defaultDial,
	}
}

func defaultDial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func (c *config) validate() error {
	switch {
	case c.dialTimeout <= 0:
		return fmt.Errorf("clamav: dial timeout must be positive, got %v", c.dialTimeout)
	case c.ioTimeout <= 0:
		return fmt.Errorf("clamav: I/O timeout must be positive, got %v", c.ioTimeout)
	case c.chunkSize < 1 || c.chunkSize > proto.MaxChunkSize:
		return fmt.Errorf("clamav: chunk size must be in [1, %d], got %d", proto.MaxChunkSize, c.chunkSize)
	case c.maxStreamSize != NoSizeLimit && c.maxStreamSize <= 0:
		return fmt.Errorf("clamav: max stream size must be positive or NoSizeLimit, got %d", c.maxStreamSize)
	case c.maxConcurrentScans < 0:
		return fmt.Errorf("clamav: max concurrent scans must be >= 0, got %d", c.maxConcurrentScans)
	case c.dialFunc == nil:
		return fmt.Errorf("clamav: dial function must not be nil")
	}
	return nil
}

// WithDialTimeout bounds connection establishment. The context passed to
// each call still applies; the earlier deadline wins.
func WithDialTimeout(d time.Duration) Option {
	return func(c *config) { c.dialTimeout = d }
}

// WithIOTimeout bounds each individual read/write on the connection. The
// deadline is refreshed before every operation, so it limits the time the
// scan makes no progress, not the total scan duration — bound that with
// the context.
func WithIOTimeout(d time.Duration) Option {
	return func(c *config) { c.ioTimeout = d }
}

// WithChunkSize sets the INSTREAM chunk payload size in bytes.
func WithChunkSize(n int) Option {
	return func(c *config) { c.chunkSize = n }
}

// WithMaxStreamSize sets the client-side payload limit in bytes, or disables
// it with NoSizeLimit. Inputs that would exceed the limit fail with
// ErrSizeLimitExceeded before the excess is sent to clamd.
//
// Set this to the same value as StreamMaxLength in your clamd.conf. If the
// client limit is larger than StreamMaxLength, oversized streams are still
// rejected — by clamd — but only after the bytes have been transferred.
func WithMaxStreamSize(n int64) Option {
	return func(c *config) { c.maxStreamSize = n }
}

// WithMaxConcurrentScans caps the number of Scan/ScanBytes/ScanFile calls
// executing at once; further calls wait for a slot or fail when their
// context expires. 0 (the default) means no client-side cap.
//
// Size this below MaxThreads in clamd.conf so a burst of uploads queues in
// the application instead of overloading clamd. Admin commands (Ping,
// Version, Stats, Reload) do not count against the cap.
func WithMaxConcurrentScans(n int) Option {
	return func(c *config) { c.maxConcurrentScans = n }
}

// WithDialFunc replaces the transport dialer. Intended for tests and for
// custom transports (e.g. proxies). The implementation is responsible for
// honoring ctx.
func WithDialFunc(fn DialFunc) Option {
	return func(c *config) { c.dialFunc = fn }
}
