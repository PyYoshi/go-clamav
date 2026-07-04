package clamav

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PyYoshi/go-clamav/internal/clamdtest"
)

func TestPing(t *testing.T) {
	forEachNetwork(t, func(t *testing.T, fake *clamdtest.Fake) {
		c := newClient(t, fake.Addr)
		if err := c.Ping(context.Background()); err != nil {
			t.Errorf("Ping() error = %v", err)
		}
	})
}

func TestPingUnexpectedReply(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	fake.SetHandler(clamdtest.RespondWith("NOT PONG\x00"))
	c := newClient(t, fake.Addr)
	err := c.Ping(context.Background())
	var protoErr *ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("error = %T(%v), want *ProtocolError", err, err)
	}
}

func TestPingDown(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	c := newClient(t, fake.Addr)
	fake.Close()
	err := c.Ping(context.Background())
	var connErr *ConnectionError
	if !errors.As(err, &connErr) {
		t.Fatalf("error = %T(%v), want *ConnectionError", err, err)
	}
	if !IsRetryable(err) {
		t.Error("unreachable clamd should be retryable")
	}
}

func TestVersion(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	c := newClient(t, fake.Addr)
	v, err := c.Version(context.Background())
	if err != nil {
		t.Fatalf("Version() error = %v", err)
	}
	if !strings.HasPrefix(v, "ClamAV ") {
		t.Errorf("Version() = %q", v)
	}
}

func TestVersionErrorReply(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	fake.SetHandler(clamdtest.RespondWith("something broke ERROR\x00"))
	c := newClient(t, fake.Addr)
	_, err := c.Version(context.Background())
	var clamdErr *ClamdError
	if !errors.As(err, &clamdErr) {
		t.Fatalf("error = %T(%v), want *ClamdError", err, err)
	}
}

func TestStats(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	c := newClient(t, fake.Addr)
	s, err := c.Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}
	if !strings.Contains(s, "POOLS:") || !strings.Contains(s, "END") {
		t.Errorf("Stats() = %q, want multi-line stats block", s)
	}
}

func TestReload(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	c := newClient(t, fake.Addr)
	if err := c.Reload(context.Background()); err != nil {
		t.Errorf("Reload() error = %v", err)
	}
}

func TestReloadUnexpectedReply(t *testing.T) {
	fake := clamdtest.New(t, "unix")
	fake.SetHandler(clamdtest.RespondWith("NOPE\x00"))
	c := newClient(t, fake.Addr)
	err := c.Reload(context.Background())
	var protoErr *ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("error = %T(%v), want *ProtocolError", err, err)
	}
}
