---
name: obliteratus-orchestrator
description: Tactical orchestration and security auditing skill for the OBLITERATUS Windows credential-exposure auditor. Use this skill to understand the v2 architecture, run the Mimikatz attack-surface audit, extend checks, or operate the loopback dashboard safely.
---

# OBLITERATUS Orchestrator

Procedural knowledge for operating and extending OBLITERATUS v2: a Windows
credential-exposure auditor whose core deliverable is the **Mimikatz playbook
run as a defensive checklist**, plus (locked) authorised red-team modules.

## Architecture (v2)

- **`cmd/obliteratus`** — CLI: `--audit` headless mode, dashboard wiring.
- **`internal/audit`** — the product: 12 Mimikatz-mapped checks
  (`RunChecks`/`BuildReport`) + browser collectors gated behind
  `--enable-collect`.
- **`internal/server`** — loopback-only HTTP API: per-run 256-bit token,
  Host allow-list, POST-only mutations, module gating, WS hub.
- **`internal/research`** — Halo's Gate indirect-syscall bridge
  (`EnergyFlow` in `energyflow_amd64.s`) + W^X injection, gated behind
  `--enable-inject`.
- **`internal/ui`** — embedded dashboard (`//go:embed`), token injected
  same-origin.

Dependency direction: `cmd → server → {audit, research, ui, ...}`; `audit`
never imports `server` (progress is an `Emitter` callback) so checks stay
unit-testable.

## Workflows

### 1. Headless audit (CI / scripted hardening review)
```powershell
obliteratus.exe --audit          # human report, exit 1 on CRITICAL/HIGH fail
obliteratus.exe --audit --json   # machine-readable
obliteratus.exe --audit --csv    # spreadsheet
```
Contract: exit 1 only when a CRITICAL or HIGH control is *failing*; warnings
and `unknown` never fail the run.

### 2. Interactive assessment (dashboard)
```powershell
obliteratus.exe [--elevate]      # loopback-only; token generated per run
# open http://127.0.0.1:8080 — 3 clicks or F2 unlocks the desktop
```
Unlock authorised modules only for sanctioned engagements:
`--enable-collect` (browser stores), `--enable-inject` (injection research).

### 3. Adding an audit check
1. Write `checkXxx() Finding` in `internal/audit/host_windows.go`
   (registry reads, locale-independent, no side effects).
2. Unobservable paths must return `StatusUnknown` — **never** `StatusPass`.
3. Register in `RunChecks`, pin the ID in `TestRunChecksShape`, add the
   README checklist row.

## Tactical invariants (do not regress)

- Listener refuses non-loopback binds.
- Every API route: loopback Host + constant-time token; mutations POST.
- WebSocket: loopback Origin **and** `?t=` token.
- Disabled modules fail closed with an actionable 403.
- Injection primitive never creates an RWX page (RW → RX transition only).
- All dashboard rendering of server data goes through `window.esc()`.

## Best Practices

- **Elevation:** audits degrade gracefully unelevated; `--elevate` only when
  checks report `unknown` due to privilege.
- **Payload targeting:** `--enable-inject` acts only on an operator-selected
  PID; verify target integrity before orchestration.
- **Telemetry:** `logLine` broadcasts operator actions to the WS hub — keep
  secrets out of progress messages.
