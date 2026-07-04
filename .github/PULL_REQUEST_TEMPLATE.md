## Summary

<!-- What changed and why. Design-level changes (public API, wire protocol,
     security defaults) must reference an accepted ADR in docs/adr/. -->

## Checklist

- [ ] `make verify` passes locally (build + lint + tests)
- [ ] `make integration` passes (required when `client.go` / `conn.go` / `commands.go` / `internal/proto/` / `docker/` changed)
- [ ] `README.md` and `README.ja.md` updated together, or the change touches neither
- [ ] `CHANGELOG.md` updated under `[Unreleased]` for user-visible changes
- [ ] No new dependencies, no assembled EICAR string, no weakened guards; design changes reference an ADR
