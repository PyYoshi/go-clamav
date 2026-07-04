# go-clamav

[![CI](https://github.com/PyYoshi/go-clamav/actions/workflows/ci.yaml/badge.svg)](https://github.com/PyYoshi/go-clamav/actions/workflows/ci.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/PyYoshi/go-clamav.svg)](https://pkg.go.dev/github.com/PyYoshi/go-clamav)

A pure-Go [clamd](https://docs.clamav.net/) (ClamAV daemon) client for
scanning untrusted user uploads before accepting them, designed **fail-closed**
from the type system up.

日本語版は [README.ja.md](README.ja.md) を参照してください。

- **Pure Go, stdlib only.** No cgo, no dependencies, `CGO_ENABLED=0` builds.
  The library speaks the clamd socket protocol directly (see
  [ADR-0001](docs/adr/0001-clamd-socket-over-libclamav.md) for why clamd
  instead of linking libclamav).
- **INSTREAM only.** File contents are streamed to clamd; clamd never needs
  filesystem access to the scanned data, and no temporary files are created.
- **Fail-closed by construction.** An error can never be mistaken for a
  clean verdict, oversized inputs are rejected before they are streamed, and
  replies the client cannot parse are errors — never guesses.
- **Context-aware.** Every call honors `context.Context` cancellation and
  deadlines, including mid-stream.
- **DoS-resistant.** Bounded reply reads, per-operation I/O timeouts, a
  client-side stream size limit, and an optional concurrency cap.

## The fail-closed contract

This library is a security control. Callers must apply exactly one rule set:

| Outcome                     | Meaning                          | Caller obligation            |
| --------------------------- | -------------------------------- | ---------------------------- |
| `err == nil && res.Clean()` | Scan completed, no detection     | The file may be accepted     |
| `res.Infected()`            | Scan completed, signature match  | Reject; quarantine and audit |
| `err != nil` (any type)     | **Verdict unknown — not clean**  | Reject (or retry, then reject) |

When `err != nil` the returned `ScanResult` is always the zero value, whose
`Verdict` is `VerdictUnknown` — so even buggy callers that ignore the error
and check `res.Clean()` do not accept the file. Never treat a scan failure
(timeouts, connection failures, `ErrSizeLimitExceeded`, ...) as "no malware
found".

## Installation

```
go get github.com/PyYoshi/go-clamav
```

Requires Go 1.26+ and a running clamd. CI covers the 1.4 LTS line
(supported until 2027-08-15) and the current regular release (1.5); the
dockerized test environment defaults to 1.5.

## Quick start

```go
client, err := clamav.New("unix:///run/clamav/clamd.sock",
    clamav.WithMaxStreamSize(25<<20),    // keep equal to clamd's StreamMaxLength
    clamav.WithMaxConcurrentScans(4),    // keep below clamd's MaxThreads
)
if err != nil {
    log.Fatal(err)
}

ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
defer cancel()

result, err := client.Scan(ctx, uploadedFile)
switch {
case err != nil:
    // Verdict UNKNOWN: reject the upload. See IsRetryable for retry hints.
    reject(err)
case result.Infected():
    quarantine(result.Signature)
default:
    accept()
}
```

A complete upload endpoint (including HTTP status mapping and health checks)
is in [examples/httpupload](examples/httpupload/main.go); a CLI scanner is in
[examples/basicscan](examples/basicscan/main.go).

## API overview

```go
func New(addr string, opts ...Option) (*Client, error)

func (c *Client) Scan(ctx context.Context, r io.Reader) (ScanResult, error)
func (c *Client) ScanBytes(ctx context.Context, data []byte) (ScanResult, error)
func (c *Client) ScanFile(ctx context.Context, path string) (ScanResult, error)

func (c *Client) Ping(ctx context.Context) error              // readiness probe
func (c *Client) Version(ctx context.Context) (string, error) // includes DB version/date
func (c *Client) Stats(ctx context.Context) (string, error)   // diagnostic text
func (c *Client) Reload(ctx context.Context) error            // admin; not for scan paths
```

`Client` is safe for concurrent use. Each command runs on its own
connection, matching clamd's one-command-per-connection session model.

### Options

| Option                       | Default | Notes                                                        |
| ---------------------------- | ------- | ------------------------------------------------------------ |
| `WithMaxStreamSize(n)`       | 25 MiB  | Client-side payload limit. **Set equal to clamd's `StreamMaxLength`.** `NoSizeLimit` disables (discouraged) |
| `WithMaxConcurrentScans(n)`  | 0 (off) | Cap concurrent scans; keep below clamd's `MaxThreads`        |
| `WithDialTimeout(d)`         | 10s     | Connection establishment                                     |
| `WithIOTimeout(d)`           | 30s     | Per-read/write no-progress limit (total time = context)      |
| `WithChunkSize(n)`           | 32 KiB  | INSTREAM chunk payload size                                  |
| `WithDialFunc(fn)`           | net.Dialer | Custom transport (tests, proxies)                         |

### Errors

All failures arrive as one of four shapes; classify with `errors.Is/As`:

| Error                  | Meaning                                        | `IsRetryable` |
| ---------------------- | ---------------------------------------------- | ------------- |
| `ErrSizeLimitExceeded` | Client- or clamd-side size limit; **not scanned** | no         |
| `*ClamdError`          | clamd replied `... ERROR`                      | no            |
| `*ProtocolError`       | Unclassifiable reply (fail-closed)             | no            |
| `*ConnectionError`     | Dial/read/write transport failure              | yes           |
| ctx cancellation       | Wrapped `context.Canceled` / `DeadlineExceeded`| no / yes      |

The library never retries on its own: an `io.Reader` cannot be replayed and
silent retries would double-stream uploads. Use `IsRetryable(err)` and
re-supply the input yourself (e.g. reopen the file) with bounded backoff.

## Addresses and deployment security

```
unix:///run/clamav/clamd.sock   # preferred
tcp://127.0.0.1:3310            # loopback / isolated private networks only
```

The clamd protocol is **unauthenticated cleartext**. Treat the address as
security-sensitive deployment configuration:

- Prefer unix sockets; use TCP only to loopback or an isolated network.
- Never expose clamd's port to untrusted networks (anyone who can reach it
  can also issue `SHUTDOWN`).
- Never derive the address from request or user input (SSRF-style pivots).
- Scheme-less addresses are rejected by `New` on purpose.

Operational hardening (clamd.conf limits, freshclam, monitoring signature
freshness, overload behavior) is covered in
[docs/operations.md](docs/operations.md).

## Testing

```
make test          # unit tests + race detector (no Docker needed)
make integration   # starts dockerized clamd, runs integration suite
make fuzz          # short fuzzing pass over the reply parser
make lint          # golangci-lint (security-heavy config) + govulncheck
make format        # gofumpt + gci formatting (via golangci-lint fmt)
```

The integration environment (see [docker/](docker/)) starts the official
`clamav/clamav` image in seconds using a minimal EICAR-only signature
database, exposes both a unix socket and loopback TCP, and uses a tiny
`StreamMaxLength` so the size limit paths are actually exercised. The EICAR
test string never appears assembled in the repository — it is stored as a
hex signature and as split string constants, and only ever exists complete
in memory during tests.

## Architecture fit

The library is the scanning client piece of the pattern used by
[GoogleCloudPlatform/docker-clamav-malware-scanner](https://github.com/GoogleCloudPlatform/docker-clamav-malware-scanner):
uploads land in an unscanned area, a worker scans them (this library →
clamd), and files are then routed to clean storage or quarantine. Run clamd
as a sidecar or dedicated service; run freshclam next to clamd, not in your
application.

## Contributing

`main` is protected by repository rulesets: changes land only through pull
requests with all CI checks green, every commit must carry a verified
signature, and pull requests are merged with a merge commit (squash and
rebase are disabled so commit signatures survive). Release tags (`v*`)
cannot be deleted or moved.

## License

MIT — see [LICENSE](LICENSE). The library talks to ClamAV over a socket and
does not link libclamav; ClamAV itself remains licensed under GPLv2.
