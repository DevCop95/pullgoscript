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

## Documented limits

These are boundaries of the current design, not bugs, and they are written
here so they are not rediscovered as surprises.

### The token is a lock on the door, not on the room

`GET /` hands the token to the page that runs the dashboard, and it cannot tell
your browser apart from any other local process that asks. Anything running in
your session with loopback access can fetch the token and then call the API
with it. There is no privilege boundary between the console and a process
running as the same user, and none is claimed.

- **Single-user workstation** (the intended deployment): a process that already
  runs as you has everything the console can do, so the token adds no exposure
  beyond what that process already has.
- **Shared host, terminal server, or a lower-privilege local process:** when
  `--enable-collect` is set the console is elevated, so a lower-privilege
  process that reads the token can ask the elevated server to export SAM/SYSTEM
  or read browser stores. Do not run the console elevated with those modules
  unlocked on a host where another account can reach loopback.

If this boundary needs to be hard rather than documented, the fix is a named
pipe with an ACL restricted to the operator's SID instead of an HTTP listener;
that is tracked in issue #6.

### `POST /v1/sys/opt` changes machine policy with no flag

It writes registry policy and disables `DiagTrack` with no startup flag and no
request body, so anyone holding the token can change machine policy without any
of the module gates. It is documented here rather than gated, because the token
holder is trusted by design (see above).

## Known intentional capabilities

These are features, not bugs — they are the reason the tool exists:

- `POST /v1/sys/cmd` executes shell commands **as the token holder**.
- `--enable-collect` decrypts browser credential stores **on the local host**.
- `POST /v1/sys/sam` exports the local SAM/SYSTEM hives with `RegSaveKeyEx`
  and decrypts the local account hashes **on the local host** (same
  `--enable-collect` gate; also requires an elevated token, which
  `--enable-collect` requests via UAC at startup).
- `--enable-inject` performs W^X process injection **on an operator-selected
  local PID**.

They are only reachable over loopback with the per-run token, and the last two
require explicit flags at startup. Hardening regressions in that chain *are*
in scope.
