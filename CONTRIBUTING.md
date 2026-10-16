# Contributing to OBLITERATUS

Thanks for helping make Windows credential exposure measurable. This document
covers the workflow and the conventions that keep the audit honest.

## Development setup

- Go 1.25+ on any OS (the audit itself only runs on Windows).
- Fork + clone, then:

```bash
make test    # gofmt check + go vet + go test ./...
make build   # windows/amd64 → bin/obliteratus.exe
```

CI runs the same gates on every PR (`gofmt`, `go vet`, `go test`, cross
compile), so a green local `make test` means a green PR.

## Adding an audit check

The whole point of this repo is that checks stay **falsifiable and honest**.

1. Add a `checkXxx() Finding` in `internal/audit/host_windows.go`.
   - Stable ID (`MK-SOMETHING`), severity, `Technique` (MITRE), `Module`
     (Mimikatz command), `Remediation` (concrete fix: key + value + reboot).
   - `Evidence` must state what was *observed* — never a bare pass/fail.
   - Any path that cannot observe must return `StatusUnknown`, **never**
     `StatusPass`. A false pass is worse than no check.
2. Register it in `RunChecks`.
3. Extend `TestRunChecksShape` (`host_windows_test.go`) with the new ID in the
   required list.
4. Document the row in `README.md`'s checklist table.

### Check design rules

- **Locale independence** — never parse `sc`/`reg` command output (localized);
  use `golang.org/x/sys/windows` APIs or registry keys.
- **Privilege independence** — registry reads over SCM queries: Defender's ACL
  denies `OpenService` even to admins.
- **No side effects** — an audit must not modify the host. State-changing
  features (tweaks, collectors) live outside `RunChecks`.

## Code conventions

- `gofmt -w .` before committing (CI fails on unformatted files).
- All server routes go through `s.guard(...)` (or `s.guardPage` for HTML) —
  never register a raw handler that skips host + token validation.
- Anything that touches user/browser data before `innerHTML` must pass
  through `window.esc()`.
- New API handlers that mutate state use `POST` (method patterns enforce it).
- Gate anything offensive behind a `--enable-*` flag with a fail-closed 403.

## Commit style

Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`,
`chore:`. Explain *why* in the body when the change isn't self-evident.

## Reporting bugs

Use GitHub issues for reproducible defects. Security-sensitive reports go
through [SECURITY.md](SECURITY.md), not the public tracker.
