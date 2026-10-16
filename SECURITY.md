# Security Policy

## Supported version

| Version | Supported |
|---|---|
| 2.x | ✅ current |
| 1.x (legacy monolith) | ❌ unmaintained — please upgrade |

## Reporting a vulnerability

If you find a vulnerability or a weakness in OBLITERATUS itself (dashboard
auth, API exposure, injection module, audit correctness), report it
**privately**:

- GitHub → **Security → Report a vulnerability** (private vulnerability
  reporting) on `DevCop95/pullgoscript`, or
- Open a minimal issue titled `[SECURITY]` with *no* exploit details and ask
  for a private channel.

Please include: affected version/commit, impact, reproduction steps and any
suggested fix. You will get an acknowledgement within 72 hours and a status
update within 10 business days. Fixes are credited in the release notes
unless you prefer otherwise.

## Threat model summary

OBLITERATUS runs a local HTTP console that can execute commands, modify
registry policy and (when unlocked) read browser stores. The assets it
protects are:

| Asset | Adversary | Control |
|---|---|---|
| API token | Local process, cross-site page | `crypto/rand` per run, constant-time compare, never logged |
| Dashboard page (carries token) | DNS rebinding, cross-origin fetch | Host header allow-list, same-origin policy, CSP |
| WebSocket console channel | Cross-site WS hijack | Loopback Origin + token (`?t=`) |
| Command/inject/collect endpoints | CSRF from hostile page | Custom header (prefers preflight), POST-only, module flags |
| Network exposure | Remote host on LAN | Loopback-only bind, enforced at `Listen` time |

**Out of scope:** physical access, kernel-level attackers, and the (by design)
operator console once the token holder is trusted.

## Known intentional capabilities

These are features, not bugs — they are the reason the tool exists:

- `POST /v1/sys/cmd` executes shell commands **as the token holder**.
- `--enable-collect` decrypts browser credential stores **on the local host**.
- `POST /v1/sys/sam` exports the local SAM/SYSTEM hives with `RegSaveKeyEx`
  and decrypts the local account hashes **on the local host** (same
  `--enable-collect` gate; also requires an elevated token).
- `--enable-inject` performs W^X process injection **on an operator-selected
  local PID**.

They are only reachable over loopback with the per-run token, and the last two
require explicit flags at startup. Hardening regressions in that chain *are*
in scope.
