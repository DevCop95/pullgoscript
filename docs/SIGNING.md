# Release signing & verification

OBLITERATUS ships offensive modules, so the artifacts will trip
SmartScreen/Defender no matter what. This document is about the *cryptographic*
guarantees we can make, and the one we cannot make yet.

## What the release pipeline produces

`.github/workflows/release.yml` runs on every `v*` tag and emits, per release:

| Artifact | What it proves |
|---|---|
| `obliteratus_<ver>_windows_<arch>.zip` | the binary + README/SECURITY/LICENSE |
| `checksums.txt` | SHA-256 of every archive |
| `checksums.txt.sig` | **cosign keyless** signature over `checksums.txt` |
| `checksums.txt.pem` | the short-lived cert that binds the signature to the workflow run |
| `*.sbom.json` | SPDX SBOM (syft) — the full dependency inventory per archive |

There is **no long-lived signing key in this repository**. The keyless
signature is bound to the GitHub Actions OIDC identity of the workflow run and
recorded in the Sigstore **Rekor** transparency log, so the signature cannot be
forged without compromising GitHub's OIDC issuer — and any use is publicly
logged.

## Verify a download (recommended)

```bash
# 0. Install cosign:  https://docs.sigstore.dev/cosign/installation/

# 1. Checksum integrity.
sha256sum -c checksums.txt   # or:  Get-FileHash -Algorithm SHA256 .\*.zip

# 2. Signature — verify the checksum file against the exact workflow identity.
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature   checksums.txt.sig \
  --certificate-identity-regexp "^https://github.com/DevCop95/obliteratus/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt
# → "Verified OK"

# 3. Transparency log entry (proves it was logged, not just signed).
rekor-cli get --artifact checksums.txt
```

`--certificate-identity-regexp` is the crux: a bare `Verified OK` only says
*someone* signed it. Pinning the identity to `DevCop95/obliteratus` is what
stops a signature from any other repository being accepted.

Reviewing the SBOM:

```bash
syft convert obliteratus_<ver>_windows_amd64.sbom.json -o table
# or grep for the modules you care about
```

## Windows Authenticode — status: **not applied**

The `.exe` files are **not** Authenticode-signed. Concretely:

- `Get-AuthenticodeSignature .\obliteratus.exe` → `Status: NotSigned`.
- SmartScreen shows "Windows protected your PC"; Defender may quarantine on
  sight of the injection / credential-collection strings. This is expected for
  an unsigned offensive tool and is **not** a build failure.

Why not applied: an Authenticode signature needs a code-signing certificate.
For a signature Windows actually trusts, that is an **EV certificate** or an
**Azure Trusted Signing** account — a paid, identity-verified credential that
must live in a secret, not in an open repository. We deliberately do **not**
check a placeholder cert into CI. Until a cert exists, the keyless cosign
signature above is the honest guarantee: *this binary came from this repo's
release workflow*, even though Windows won't validate it natively.

### If you hold a certificate (operator/local signing)

Sign a built binary yourself — this works today with a cert in
`CurrentUser\My`:

```powershell
# $cert = (Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)[0]
signtool sign `
  /fd SHA256 `
  /tr http://timestamp.digicert.com /td SHA256 `
  /n "Your Company Name" `
  .\obliteratus.exe .\oblpack.exe

Get-AuthenticodeSignature .\obliteratus.exe   # → Valid
```

Timestamping with `/tr` is not optional: without it the signature dies the
moment the certificate expires.

### Wiring a cert into the release workflow later

When an EV cert or Azure Trusted Signing is available, add a `signs` entry to
`.goreleaser.yml` that runs **after** the build and **before** archiving, so
the signed bytes are what lands in the zip and its checksum. Sketch
(non-functional until the cert exists):

```yaml
signs:
  - id: authenticode
    cmd: signtool
    artifacts: binary           # sign the .exe, not the archive
    signature: "${artifact}"
    args:
      - sign
      - /fd            # /fd SHA256
      - /tr http://timestamp.digicert.com /td SHA256
      - /n "Your Company Name"
      - "${artifact}"
```

The cert/credential must be injected as a GitHub secret (base64 PFX imported
into the runner's store, or an Azure Trusted Signing OIDC login) — it must
never be committed. Note that signing the binaries changes their hashes, so the
Authenticode step has to precede both the archive and `checksums.txt`; that is
why it lives in the `signs` pipe rather than as a post-release `signtool` job.

## Threat-model note

The cosign guarantee is about **provenance** (which repo/workflow built this),
not **safety** (that the code is benign). OBLITERATUS is dual-use by design;
provenance plus a readable SBOM plus a pinned toolchain is the whole point.
See `SECURITY.md` for the runtime threat model.
