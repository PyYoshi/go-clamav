package clamav

import "testing"

func TestParseAddress(t *testing.T) {
	tests := []struct {
		addr        string
		wantNetwork string
		wantTarget  string
		wantErr     bool
	}{
		{"unix:///run/clamav/clamd.sock", "unix", "/run/clamav/clamd.sock", false},
		{"unix://@clamd", "unix", "@clamd", false},
		{"tcp://127.0.0.1:3310", "tcp", "127.0.0.1:3310", false},
		{"tcp://localhost:3310", "tcp", "localhost:3310", false},
		{"tcp://[::1]:3310", "tcp", "[::1]:3310", false},

		{"", "", "", true},
		{"unix://", "", "", true},
		{"unix://relative/path.sock", "", "", true},
		{"tcp://", "", "", true},
		{"tcp://127.0.0.1", "", "", true},         // missing port
		{"tcp://:3310", "", "", true},             // missing host
		{"/run/clamav/clamd.sock", "", "", true},  // scheme-less path
		{"127.0.0.1:3310", "", "", true},          // scheme-less host:port
		{"udp://127.0.0.1:3310", "", "", true},    // unsupported scheme
		{"http://127.0.0.1:3310", "", "", true},   // unsupported scheme
		{"UNIX:///run/clamd.sock", "", "", true},  // schemes are case-sensitive
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			network, target, err := parseAddress(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseAddress(%q) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
			}
			if network != tt.wantNetwork || target != tt.wantTarget {
				t.Errorf("parseAddress(%q) = (%q, %q), want (%q, %q)",
					tt.addr, network, target, tt.wantNetwork, tt.wantTarget)
			}
		})
	}
}
