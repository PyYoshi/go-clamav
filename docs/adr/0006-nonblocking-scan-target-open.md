# ADR-0006: Open scan targets non-blocking on unix

- Status: Accepted
- Date: 2026-08-15

## Context

`ScanFile` stats the path first and rejects non-regular files, then opens
it and re-checks the type on the descriptor. Between the stat and the open
the path can be swapped for a FIFO by anyone with write access to the
directory; a plain `open(2)` of a FIFO with no writer blocks until a
writer appears, `os.Open` cannot be cancelled by a context, and the
authoritative fstat re-check only runs after the open returns. A 2026-08
security audit (finding F-3) demonstrated the stall: one goroutine and one
scan-concurrency slot pinned indefinitely. The godoc claim that "a FIFO
path cannot block the open" was an overstatement — the pre-open stat is a
fast-path convenience, not a guarantee.

The attack precondition is narrow (write access to the scanned directory,
which in the intended deployment belongs to the application itself), so
this is hardening, not a fix for a practical fail-open.

## Decision

On unix, `ScanFile` opens the target with
`os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)` via a build-tagged
`openScanTarget` helper. On non-unix platforms the helper is a plain
`os.Open`. The existing descriptor re-check (`f.Stat` + `checkScanTarget`)
remains the authoritative gate that rejects everything non-regular.

## Rationale

- POSIX defines `O_NONBLOCK` on a FIFO read-end open to return
  immediately even with no writer, and to have no effect on `read(2)`
  from regular files — so the flag needs no `fcntl` reset after the
  fstat re-check accepts the file. This combination was decisive: one
  flag closes the stall with zero behavior change for legitimate targets.
- Go runtime detail, verified: `os.OpenFile` with `O_NONBLOCK` attempts
  netpoll registration; for regular files this fails (Linux `epoll_ctl`
  returns `EPERM`, kqueue platforms explicitly refuse `S_IFREG`) and the
  runtime falls back to ordinary blocking file I/O, so `StreamAll` reads
  behave exactly as before.
- `syscall.O_NONBLOCK` is provided by the standard library on every GOOS
  matched by `//go:build unix`; the zero-dependency policy (ADR-0003) is
  unaffected.

## Considered objections

- A watchdog goroutine racing the open against the context was rejected:
  it leaks a permanently blocked goroutine and file descriptor per attack,
  which is the very resource pin the change removes.
- Windows named pipes have no equivalent indefinite-block on `CreateFile`
  open for the paths `ScanFile` accepts, so the non-unix helper stays a
  plain `os.Open` rather than porting flag emulation.
- Device files opened with `O_NONBLOCK` may succeed where a blocking open
  would hang (e.g. a swapped-in tape device); acceptable — the fstat
  re-check rejects them as non-regular either way, which is fail-closed.

## Consequences

- The `ScanFile` godoc claim becomes true on unix: a FIFO path cannot
  block the open, whether present at the type check or swapped in after.
- Platform-specific behavior now lives in two small build-tagged files
  (`scanfile_unix.go`, `scanfile_other.go`); CI builds linux only, so the
  non-unix file is compile-checked manually (`GOOS=windows go build`)
  when touched.
- A unit test opens a writer-less FIFO through the helper directly,
  pinning the no-block property against regressions.
