# Architecture

## Package map

```
cmd/obliteratus        CLI entrypoint: flags, --audit mode, wiring
internal/
  audit/               The assessment engine (the product)
    finding.go           Finding/Report types, severity, CSV/JSON rendering
    host_windows.go      12 Mimikatz-playbook checks (registry + token + services)
    collector_windows.go Authorised browser collectors (--enable-collect)
    unsupported_other.go Build stubs for non-Windows CI
  server/              Loopback HTTP API
    middleware.go        Host allow-list + token guard + security headers
    ws.go                Authenticated WebSocket hub
    server.go            Routes, handlers, module gating, loopback bind
    shell_*.go           Operator-console shell adapter
  research/            Offensive research primitives (windows/amd64)
    energyflow_amd64.s   Halo's Gate indirect-syscall trampoline
    inject_windows.go    W^X injection routine (RW→RX, never RWX)
  token/               Per-run 256-bit token (crypto/rand, constant-time cmp)
  ui/                  //go:embed dashboard + token injection
  elevate/             Opt-in UAC relaunch
  winutil/             Process table, telemetry hardening
```

Dependency direction is strictly downward:
`cmd → server → {audit, research, ui, winutil, token, elevate}`.
The `audit` package never imports `server` (progress is an `Emitter` callback),
so checks are unit-testable without HTTP.

## Request flow

```
browser ── GET / ──────────────► guardPage(host check) ─► ui.Render(token)
browser ── GET /v1/... ────────► guard(host+token) ──────► handler
browser ── WS /ws?t=<token> ───► origin+token ──────────► hub clients
                                     │
audit/report handler ──► audit.BuildReport() ──► registry/token/SCM probes
collect handler ──────► gated? 403 : audit.Collect*() ──► hub chunks
```

## Security invariants (pinned by tests)

1. **Loopback only.** `Server.ListenAndServe` refuses any address whose host
   is not loopback. `TestRefusesNonLoopbackBind` pins it.
2. **Every API route requires host + token.** The custom
   `X-Signal-Token` header forces a CORS preflight for cross-origin JS, and
   no preflight is ever approved — this is the CSRF boundary.
3. **Host header allow-list.** `127.0.0.1`, `localhost`, `::1` only. This is
   the DNS-rebinding boundary (an attacker DNS name pointing at 127.0.0.1
   still cannot read the token out of the page).
4. **WebSocket: origin AND token.** `TestWebSocketRequiresTokenAndOrigin`
   exercises all three handshake outcomes.
5. **Module gating fails closed.** Disabled modules return 403 + hint; there
   is no code path from a disabled flag to collector/injector code.
6. **No RWX memory in the injection primitive.** Pages are allocated
   `PAGE_READWRITE`, written, then flipped to `PAGE_EXECUTE_READ` — the
   classic W^X discipline, documented for defenders in `docs/HALOS_GATE.md`.

## Threat model (dashboard)

| Adversary | Capability | Mitigation |
|---|---|---|
| Web page open in the operator's browser | Arbitrary fetch/WS to 127.0.0.1 | Custom header (preflight), Origin check, token never readable cross-origin |
| DNS rebinding domain | Resolves to 127.0.0.1 with attacker's Host | Host allow-list on every route |
| Other local processes | See the listening port, guess the token | 256-bit random token, constant-time compare |
| Other local users | Read the process's memory / page | OS DACLs; token lives only in memory + same-origin page |
| Remote LAN host | Connect to the port | Loopback bind enforced at `Listen` |

**Explicit non-goals:** defending the host from kernel attackers; hiding the
dashboard's existence (the 404 facade is UX, not a control); multi-user
authorization (the token holder *is* the operator).

## Why a per-run token instead of a login?

The tool runs on the operator's own machine for minutes at a time. A login
page would add a credential to store and phish; a random per-run token has no
reuse window, cannot be derived (unlike the v1 PID scheme), and is delivered
only where same-origin policy already defines "the operator".

## Build variants

| Variant | Command | Notes |
|---|---|---|
| Console (default) | `make build` | Logs + `--audit` output visible |
| Windowed | `make build-windowed` | `-H=windowsgui`; no console (no `--audit` stdout) |
| Elevated manifest | see `build/obliteratus.exe.manifest` | Optional `requireAdministrator` via a `.syso` step; default path is the opt-in `--elevate` ShellExecuteW relaunch |
