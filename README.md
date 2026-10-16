# OBLITERATUS — Windows Credential Exposure Auditor

### The Mimikatz playbook, run as a defensive checklist

<p align="center">
  <img src="docs/img/obliteratus.png" alt="OBLITERATUS dashboard" width="100%">
</p>

[![CI](https://github.com/DevCop95/pullgoscript/actions/workflows/ci.yml/badge.svg)](https://github.com/DevCop95/pullgoscript/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-lightgrey?style=flat)
![License](https://img.shields.io/badge/license-MIT-green?style=flat)

**OBLITERATUS** answers one question — *would Mimikatz work against this host?* — and answers it with evidence: registry state, token privileges, service configuration and browser store exposure, each mapped to the exact Mimikatz module and MITRE technique it corresponds to.

It ships as a single binary with two modes:

| Mode | Command | Audience |
|---|---|---|
| **Headless audit** | `obliteratus.exe --audit` | CI, scripted hardening reviews, blue-team baselines |
| **Local dashboard** | `obliteratus.exe` | Operators who want the interactive console on `127.0.0.1` |

Offensive research modules (credential collection, indirect-syscall injection) are **compiled in but locked**: they answer `403` until the operator passes `--enable-collect` / `--enable-inject`.

---

## ⚡ Quick start

```powershell
# build
go build -o bin\obliteratus.exe .\cmd\obliteratus

# headless attack-surface audit (exit code 1 = CRITICAL/HIGH control failing)
bin\obliteratus.exe --audit

# machine-readable variants
bin\obliteratus.exe --audit --json > report.json
bin\obliteratus.exe --audit --csv  > report.csv

# interactive dashboard (loopback only, ephemeral 256-bit token)
bin\obliteratus.exe
# → http://127.0.0.1:8080/   [add --elevate for privileged checks]
```

Or use the Makefile: `make build`, `make audit`, `make test`.

---

## 🔬 The audit checklist

Every finding carries a stable ID, severity, evidence, remediation, the MITRE technique and the Mimikatz module it maps to.

| ID | Control | Mimikatz module | MITRE | Severity |
|---|---|---|---|---|
| `MK-WDIGEST` | WDigest does not cache plaintext credentials | `sekurlsa::wdigest` | T1003.001 | CRITICAL |
| `MK-AUTOLOGON-PASS` | No cleartext password in Winlogon | `winlogon\DefaultPassword` | T1552.001 | CRITICAL |
| `MK-LSASS-PPL` | LSASS runs as a protected process | `sekurlsa::logonpasswords` | T1003.001 | HIGH |
| `MK-CREDGUARD` | Credential Guard / VBS enabled | `sekurlsa::logonpasswords` | T1003.001 | HIGH |
| `MK-SEDEBUG` | SeDebugPrivilege not enabled in token | `privilege::debug` | T1134.001 | HIGH |
| `MK-AV` | Endpoint protection installed and enabled | — | T1562.001 | HIGH |
| `MK-PSLOG` | PowerShell Script Block Logging enabled | — | T1059.001 | MEDIUM |
| `MK-LAPS` | Managed local admin password in use | — | T1078.002 | MEDIUM |
| `MK-AUTOLOGON` | Automatic logon disabled | `lsadump::secrets` | T1003.004 | MEDIUM |
| `MK-SYSMON` | Sysmon / EDR telemetry installed | — | — | LOW |
| `MK-CACHEDLOGONS` | Cached domain logon count reviewed | `lsadump::cache` | T1003.005 | INFO |
| `MK-CONTEXT` | Audit execution context (elevated or not) | — | — | INFO |

Checks degrade to `unknown` (never to a false `pass`) when a privilege or asset is missing — an honest audit reports what it could *not* see. Adding a check is one function plus one line in `RunChecks`; see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 🖥️ Dashboard

Local-only web console on `127.0.0.1` — sidebar layout with modal confirmations, toasts and CSV export:

- **Attack-Surface Audit** — run the Mimikatz checklist interactively, CSV export.
- **Processes** — live process table with filter and PID selection.
- **System Optimizer** — one-click telemetry/privacy hardening (registry + `DiagTrack`).
- **Terminal** — command console with streamed output.
- **Hex viewer** — payload integrity inspection.
- **Architect / Decrypter** — the *authorised* modules (locked by default): browser credential & cookie collection, Identity Nexus correlation, local SAM hash dump (`lsadump::sam`), injection research. Unlock with `--enable-collect` / `--enable-inject`.

<p align="center">
  <img src="docs/img/notfound.png" alt="404 facade" width="55%">
  <br><i>The console hides behind a simulated Apache 404 until the handshake (3 clicks or F2) — cosmetic only; the real boundary is the per-run token.</i>
</p>

---

## 🔒 Security model

OBLITERATUS v1 had critical local exposure holes; v2 closes them and the test-suite pins the behaviour closed:

| # | v1 problem | v2 control |
|---|---|---|
| 🔴 | Listened on **`:8080` (all interfaces)** — LAN-reachable console | Binds `127.0.0.1` only; `ListenAndServe` **refuses** non-loopback addresses |
| 🔴 | Token derived from the **PID** (visible to any process) and echoed to unauthenticated `GET /` | 256-bit `crypto/rand` token, regenerated per run, constant-time compare |
| 🔴 | `CheckOrigin: return true` — **any web page could open the WebSocket** and drive the console | Origin must be loopback **and** `?t=` token must match |
| 🔴 | No Host validation — **DNS rebinding** could read the token from the page | Every route rejects non-loopback `Host` headers |
| 🟠 | Mixed GET mutations, no method enforcement | `ServeMux` method patterns → automatic `405` on wrong verbs |
| 🟠 | Token in HTML readable cross-origin (no CSP/headers) | Same-origin only + CSP, `nosniff`, `DENY` framing, `no-store` |
| 🟠 | DOM XSS: DB-derived URLs rendered via `innerHTML` | All server data escaped through `window.esc()` before `innerHTML` |
| 🟡 | Auto-UAC on every start | Elevation opt-in (`--elevate`) |
| 🟡 | Credentialed collectors reachable by default | Locked behind `--enable-collect` / `--enable-inject`, fail closed with actionable `403` |

**Trust boundary:** anyone who can read the dashboard page (loopback, same-origin) is the operator. Cross-site pages can *reach* the port but cannot read responses, cannot set the custom header without a preflight we never approve, and cannot complete the WebSocket handshake. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full threat model.

---

## 🗂️ Architecture

```
cmd/obliteratus/        CLI: flags, --audit mode, wiring
internal/
  audit/                ★ Mimikatz attack-surface checks + report (JSON/CSV)
    host_windows.go       12 controls: WDigest, PPL, CredGuard, SeDebug…
    collector_windows.go  authorised browser collectors (--enable-collect)
    sam_windows.go         lsadump::sam: RegSaveKeyEx + [MS-SAMR] hash chain
    regf.go                offline registry-hive parser (regf reader)
  server/               Loopback HTTP API, auth middleware, WS hub, handlers
  research/             Halo's Gate indirect-syscall bridge + injection (amd64)
  token/                Per-run 256-bit token (crypto/rand, constant-time cmp)
  ui/                   Embedded dashboard (//go:embed)
  elevate/              Opt-in UAC relaunch
  winutil/              Process table, telemetry hardening
docs/                   HALOS_GATE research note, architecture, images
build/                  Manifest for optional requireAdministrator builds
```

- **Research notes:** [docs/HALOS_GATE.md](docs/HALOS_GATE.md) — SSN recovery, indirect syscalls, W^X page transitions (`NtAllocateVirtualMemory` RW → `NtProtectVirtualMemory` RX: no RWX page ever exists).
- **Build details:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## 🧪 Testing

```bash
make test    # go vet + go test ./...   (server auth, WS handshake, report, audit)
make build   # windows/amd64 binary
make audit   # run the audit against this machine
```

CI runs `gofmt`, `go vet`, `go test` on Windows and cross-compiles from Linux on every push/PR.

---

## 🤝 Contributing

New audit checks, fixes and docs are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Found a vulnerability in the dashboard/API? See [SECURITY.md](SECURITY.md).

## 📄 License

[MIT](LICENSE) © DevCop95 (Yared Henríquez).

## ⚠️ Disclaimer

OBLITERATUS is for **authorized security assessment, research and education** on systems you own or are contracted to test. The credential-collection and injection modules are deliberately locked; unlocking them is an explicit acknowledgement that your engagement permits their use. Unauthorized access to computer systems is illegal.

---
*Assume breach. Audit the credentials before someone else does.*
