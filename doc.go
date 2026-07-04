// Package clamav is a pure-Go client for clamd, the ClamAV daemon, designed
// for scanning untrusted user uploads before accepting them.
//
// The library talks to clamd over its socket protocol (unix:// or tcp://)
// and streams file contents with the INSTREAM command, so clamd never needs
// filesystem access to the scanned data and no temporary files are involved.
//
// # Fail-closed contract
//
// This is a security control. Callers MUST apply the following rules:
//
//   - result.Infected() == true: reject (and quarantine/audit) the file.
//   - result.Clean() == true: the file may be accepted.
//   - err != nil (any error, any type): the verdict is UNKNOWN. The file
//     must NOT be accepted. Reject it or retry; see [IsRetryable].
//
// When an error is returned the ScanResult is always the zero value, whose
// Verdict is [VerdictUnknown]; a zero ScanResult never reports Clean() true.
// Never treat a scan failure — including [ErrSizeLimitExceeded], timeouts,
// and connection failures — as "no malware found".
//
// # Deployment notes
//
// The clamd protocol is unauthenticated cleartext. Connect over a unix
// socket, or over TCP only on loopback or an isolated private network.
// Never expose clamd to untrusted networks and never derive the address
// passed to [New] from request data.
//
// The address, like the rest of the configuration, is fixed at [New] time.
// Signature freshness, StreamMaxLength, and scan limits are controlled by
// the clamd deployment (clamd.conf and freshclam); see docs/operations.md
// in the repository for hardening guidance.
package clamav
