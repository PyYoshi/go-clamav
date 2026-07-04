# Operating go-clamav in production

go-clamav is the client half of a scanning pipeline; most of the security
posture lives in how clamd is deployed and configured. This document covers
the operational side of the fail-closed contract.

## Topology

Run clamd close to the scanning workers, with freshclam next to clamd:

```
uploads ──► worker (go-clamav) ──unix socket / loopback tcp──► clamd ◄── freshclam ◄── signature mirror
                 │
                 ├── clean  ──► permanent storage
                 └── infected/unknown ──► quarantine / reject
```

- **Sidecar** (same pod/host): use `unix://`; simplest and preferred.
- **Dedicated service**: use `tcp://` on an isolated network. The protocol
  is unauthenticated cleartext — anyone who can reach the port can scan,
  `RELOAD`, or `SHUTDOWN` your daemon. Never expose it publicly; wrap it in
  a mesh/VPN if it must cross hosts.
- Do not run freshclam inside application containers; one clamd + one
  freshclam per deployment unit is enough.

## clamd.conf: recommended baseline

```
# Socket (pick one, or both)
LocalSocket /run/clamav/clamd.sock
LocalSocketMode 660          # group-readable by the app user, not world
# TCPSocket 3310
# TCPAddr 10.0.0.5           # never 0.0.0.0 on multi-tenant networks

# Size limits — the single most important DoS knob.
StreamMaxLength 25M          # MUST match WithMaxStreamSize in the client
MaxScanSize 100M             # total unpacked bytes scanned per file
MaxFileSize 25M              # largest unpacked file examined
MaxRecursion 12              # archive nesting depth
MaxFiles 1000                # files per archive

# Concurrency — size the client's WithMaxConcurrentScans below this.
MaxThreads 8
MaxQueue 32

# Hygiene
IdleTimeout 30
ReadTimeout 120              # clamd-side stall protection
Foreground yes               # under a supervisor / container
```

Client/server alignment rules:

- `WithMaxStreamSize` **equal to** `StreamMaxLength`. If the client limit is
  larger, oversized uploads are still rejected but only after transferring
  the bytes; if smaller, you reject files clamd would have accepted.
- `WithMaxConcurrentScans` **below** `MaxThreads`, so bursts queue in the
  application (bounded by each request's context) instead of piling into
  clamd's queue.
- The client's `WithIOTimeout` (default 30s) bounds *stalls*; the context
  you pass bounds the *whole scan*. Large archives can legitimately take
  tens of seconds — size scan contexts accordingly (the examples use 2m).

## Signature freshness

A scanner with stale signatures returns confident, wrong `Clean` verdicts.
Treat freshness as an SLO:

- Run freshclam in daemon mode next to clamd (it notifies clamd to reload).
- Monitor freshness from the application side with `Version(ctx)`:

  ```
  ClamAV 1.4.3/27700/Wed Jul  1 08:32:03 2026
         └─┬──┘ └─┬─┘ └────────┬──────────┘
        engine   DB version   DB publication date
  ```

  Alert when the publication date is older than ~48h (ClamAV publishes
  daily updates).
- `Reload(ctx)` exists for setups where freshclam cannot signal clamd, but
  reloads briefly spike clamd memory/latency — never call it from a
  scanning code path.

## Health checks and failure behavior

- **Readiness**: `Ping(ctx)` with a short timeout (the httpupload example
  wires this into `/healthz`). Under fail-closed semantics, "clamd down"
  means "all uploads rejected" — surfacing that through readiness lets your
  platform stop routing traffic instead of serving 503s.
- **Liveness of the pipeline**: periodically scan a known-infected sample
  (the EICAR payload from a secret store or assembled in memory) and alert
  if it does not come back `VerdictInfected`. This catches "empty/corrupt
  database" states that `Ping` cannot.
- **Queue visibility**: `Stats(ctx)` exposes clamd's thread/queue state as
  text; export the `THREADS`/`QUEUE` lines if you need saturation metrics.

When clamd is down you have two sound strategies — both reject *acceptance*:

1. **Reject uploads** with 503 + `Retry-After` (simplest; see example).
2. **Quarantine-and-queue**: store the file in a non-served quarantine
   area, enqueue a scan job, and only promote to real storage after a clean
   verdict. Better UX, same guarantee: unscanned bytes are never served.

## Retry guidance

The library never retries. In your worker:

- `IsRetryable(err) == true` (connection failures, deadline expiry): retry
  with fresh input, bounded attempts, exponential backoff + jitter.
- `IsRetryable(err) == false`: do not retry.
  - `ErrSizeLimitExceeded` — the file cannot be scanned under current
    limits: reject it, or raise both limits deliberately.
  - `*ClamdError` / `*ProtocolError` — investigate; repeated occurrences
    usually mean a clamd misconfiguration or version skew.
- `result.Infected()` is a verdict, not an error: quarantine, audit-log the
  signature (`result.Signature`), and never retry hoping for a different
  answer.

## Logging discipline

Log verdicts, signatures, sizes, durations, and error classifications —
never scanned content. The library's error strings follow this rule; keep
your wrapping code to the same standard. Signature names (e.g.
`Win.Test.EICAR_HDB-1`) are safe and useful audit data.

## Version compatibility

The reply parser is prefix-agnostic and suffix-driven, which covers the
reply-format drift observed across clamd versions ("stream:" vs older
"instream (local):"). CI pins clamd 1.4 (LTS, supported until 2027-08-15)
and 1.5 (current regular release) as required checks and tracks
`clamav/clamav:latest` in a scheduled canary job, so upstream protocol
drift surfaces as signal rather than sudden breakage.

Version policy: prefer the LTS line in production — ClamAV designates LTS
versions at release time (roughly every two years; regular releases like
1.5 are never promoted afterwards), and non-LTS lines historically reach
EOL a few months after the next feature release. When the next LTS ships,
bump the compose default and the CI matrix together.
