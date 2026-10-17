<!--
Thanks for the PR. Keep it to one topic; explain *why* in the description when
the diff alone does not make it obvious.
-->

## What changed

<!-- One or two sentences. Link the issue this closes, if any. -->

Closes #

## Why

<!-- The problem, not the patch. If it fixes a false PASS or a security
     control, say so explicitly. -->

## How it was verified

<!-- Commands you ran and what they printed. "go test ./... passes" is the
     baseline, not evidence for a behavioural change. -->

## Checklist

- [ ] `gofmt -l .` is empty and `go vet ./...` is clean.
- [ ] `go test ./...` passes locally.
- [ ] New behaviour has a test; a fix has a test that fails without it.
- [ ] No security control was weakened (token checks, Host/Origin guards,
      `s.guard(...)`, fail-closed `403`s, `StatusUnknown` over false `PASS`).
- [ ] Any `//#nosec` carries a specific reason on the same line, and any rule
      added to the `-exclude` list in `.github/workflows/ci.yml` has its
      rationale written next to it.
- [ ] `SECURITY.md` / `docs/SIGNING.md` / `README.md` updated if a capability,
      flag or artifact changed.
- [ ] No secret, token, certificate or private key is included — including in
      test fixtures and example output.
