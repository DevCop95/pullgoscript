# Contributing to OBLITERATUS

Thanks for helping make Windows credential exposure measurable. This document
covers the workflow and the conventions that keep the audit honest.

## Development setup

- Go 1.26.9+ on any OS (the audit itself only runs on Windows). This is the
  floor pinned in `go.mod`; the CI vuln-scan job reads it, so an older toolchain
  fails the build.
- Fork + clone, then:

```bash
make test    # gofmt check + go vet + go test ./...
make build   # windows/amd64 → bin/obliteratus.exe
```

CI runs the same gates on every PR — `gofmt`, `vet + test (windows)` (with a
coverage floor), `cross-compile (linux → windows)`, `govulncheck`, `gosec
(static analysis)` and `fuzz smoke (parsers)` — so a green local run means a
green PR.

## Testing and tooling

Every gate below runs in CI; run them locally before pushing. `make sast`,
`make fuzz-check` and `make cover` wrap the three you cannot get from
`go test ./...` alone — if you do not have `make` installed (it is not needed to
build the project), run the underlying commands straight out of the `Makefile`.

- **Tests** — `go test ./...`. The coverage gate is a ratchet: if your change
  raises coverage, raise `min` in `.github/workflows/ci.yml` in the same commit.
  Never lower it to make a build green. `make cover` prints the total.
- **Fuzzing** — the parsers that eat attacker-influenced input have fuzz targets
  (`FuzzRegf`, `FuzzParseRep`, `FuzzUnpack`, `FuzzMaskRoundTrip`,
  `FuzzSanitizeName`). Seeds run as ordinary tests; to actually fuzz one:

  ```bash
  go test -run='^$' -fuzz=FuzzRegf -fuzztime=60s ./internal/audit
  ```

  A crasher is written to `testdata/fuzz/<Target>/` — commit it as a
  regression seed and fix the bug.
- **Static analysis** — `gosec -exclude=G103,G104 ./...` must report zero
  findings. If a finding is a false positive, do not add a rule to the exclude
  list: annotate the line instead, with the reason, as
  `//#nosec G304 -- <why this path cannot be attacker-controlled>`. The exclude
  list is for rules whose *every* instance is deliberate, and each entry there
  is justified in a comment.
- **Vulnerabilities** — `govulncheck ./...` must be clean. It is
  reachability-aware, so a finding means your code calls the vulnerable symbol.

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
through [SECURITY.md](SECURITY.md), not the public tracker. Participation in
this project is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).
