# ADR-0004: No exported scanner interface; document the consumer-side idiom

- Status: Accepted
- Date: 2026-07-05

## Context

Consumers want to unit-test code that depends on `*clamav.Client` without a
running clamd. Three options were evaluated:

1. **Consumer-side interfaces** — each consumer defines the smallest
   interface it needs; `*Client` satisfies it implicitly (Go's structural
   typing). Ship a compile-checked example.
2. **A public fake clamd** — promote the internal test server
   (`internal/clamdtest`) to a public `clamavtest` package, httptest-style,
   so consumers run the real `Client` against scripted replies.
3. **An exported `Scanner` interface** on the library itself.

`ScanResult` already has exported fields (`Verdict`, `Signature`, `Raw`),
so consumer-written doubles can fabricate any outcome today. Per the design
gate in AGENTS.md, a public API decision requires an ADR.

## Decision

The library exports **no scanner interface**. The consumer-side idiom is
demonstrated by a compiled, tested example in `examples/mockscan`
(interface definition, compile-time assertion, fail-closed mock rules).
Promoting the internal fake to a public `clamavtest` package is **deferred,
not rejected** — to be revisited in a new ADR if real demand appears.

## Rationale

- Implicit satisfaction makes a consumer-defined interface lossless and
  strictly more flexible: each consumer picks exactly the method subset it
  uses, and `var _ scanner = (*clamav.Client)(nil)` detects signature
  drift at compile time.
- An exported interface freezes the method set as a compatibility
  commitment: adding a future `ScanStream` or IDSESSION-backed method
  would break every third-party implementation and decorator.
- This library's value is a single audited implementation of a security
  control (ADR-0001, ADR-0003); an exported interface invites substitute
  implementations of the scan path.
- Hand-rolled mocks tend to default to "clean", which teaches fail-open
  habits; the example encodes the safe rules instead (never default to
  clean; zero `ScanResult` on error; test clean/infected/error at minimum).

## Considered objections

- *Generated mocks default to zero values, so an exported interface would
  be mostly harmless* — true (`ScanResult`'s zero value is `VerdictUnknown`
  and `Clean() == false` by design), but harmless is not a reason to
  export.
- *`http.RoundTripper` is an exported, widely-mocked interface* — it
  exists for middleware composition with real alternative transports; no
  alternative scanner implementation belongs to this module.
- *A fake server tests more than mocks can* — acknowledged. The internal
  fake stays maintained by the library's own tests, so promotion remains
  cheap if demand materializes.

## Consequences

- The `Scan` method signature is a de-facto stability contract; the
  example's compile-time assertion (and consumers') will surface breakage.
- `internal/clamdtest` stays internal and unchanged.
- `examples/mockscan` is built by CI and run by `make test`, so the
  documented idiom can never silently rot.
