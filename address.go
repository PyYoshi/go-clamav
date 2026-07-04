package clamav

import (
	"fmt"
	"net"
	"strings"
)

// parseAddress splits a clamd address into a dial network and target.
//
// Supported forms:
//
//	unix:///run/clamav/clamd.sock  (absolute path)
//	unix://@clamd                  (Linux abstract socket)
//	tcp://127.0.0.1:3310
//	tcp://[::1]:3310
//
// Scheme-less addresses are rejected: requiring an explicit scheme removes
// any ambiguity between socket paths and host:port strings.
func parseAddress(addr string) (network, target string, err error) {
	switch {
	case strings.HasPrefix(addr, "unix://"):
		path := strings.TrimPrefix(addr, "unix://")
		if path == "" {
			return "", "", fmt.Errorf("clamav: address %q has an empty socket path", addr)
		}
		if path[0] != '/' && path[0] != '@' {
			return "", "", fmt.Errorf("clamav: unix socket path in %q must be absolute or abstract (start with '/' or '@')", addr)
		}
		return "unix", path, nil
	case strings.HasPrefix(addr, "tcp://"):
		hostport := strings.TrimPrefix(addr, "tcp://")
		host, port, err := net.SplitHostPort(hostport)
		if err != nil {
			return "", "", fmt.Errorf("clamav: invalid tcp address %q: %w", addr, err)
		}
		if host == "" || port == "" {
			return "", "", fmt.Errorf("clamav: tcp address %q must include both host and port", addr)
		}
		return "tcp", hostport, nil
	default:
		return "", "", fmt.Errorf("clamav: address %q must use the unix:// or tcp:// scheme", addr)
	}
}
