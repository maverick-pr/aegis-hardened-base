# aegis-hardened-base

[![build-scan-sign](https://github.com/maverick-pr/aegis-hardened-base/actions/workflows/build.yml/badge.svg)](https://github.com/maverick-pr/aegis-hardened-base/actions/workflows/build.yml)

A free, scan-gated base image with **Python 3.13** and **Node.js 22 LTS** on Google's
distroless runtime, built for AI delivery work in regulated sectors (HIPAA, PCI-DSS, SOC-2).
Every published image has **zero fixable CVEs at any severity** — Trivy and Grype gate the
build, and it is rebuilt weekly against the current Debian security archive.

```bash
docker pull ghcr.io/maverick-pr/aegis-hardened-base:latest
```

## What "zero CVEs" means here — read this

- **Zero fixable** vulnerabilities, LOW included, verified by two independent scanners on every build.
  If a fix exists anywhere upstream and the image does not have it, the build fails and nothing is published.
- **Not zero findings.** The Debian 12 base carries CVEs that Debian has classified `will_not_fix` /
  `fix_deferred` (glibc, gcc runtime) and one OpenSSL 3.0 HIGH with no upstream fix. They are listed with
  justification and exit conditions in [SECURITY.md](SECURITY.md#accepted-residual-risk-register), and
  `make audit` prints every one of them unsuppressed. If a README ever tells you an image has literally zero
  CVEs, run `grype` on it.
- **A CVE count is a date.** Pull by digest, verify the signature, and rebuild on your schedule — see below.

## Verify before you pull

Images are signed keylessly by the GitHub Actions workflow (Sigstore, recorded in the public Rekor log).
No private key exists anywhere.

```bash
cosign verify ghcr.io/maverick-pr/aegis-hardened-base:latest \
  --certificate-identity-regexp '^https://github.com/maverick-pr/aegis-hardened-base/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

SBOM (SPDX) is attached as an attestation:

```bash
cosign verify-attestation --type spdxjson ghcr.io/maverick-pr/aegis-hardened-base:latest \
  --certificate-identity-regexp '^https://github.com/maverick-pr/aegis-hardened-base/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com | jq -r .payload | base64 -d | jq .predicate
```

## What is inside

| | |
|---|---|
| Base | `gcr.io/distroless/cc-debian12:nonroot`, digest-pinned |
| Python | 3.13.x built from SHA-256-verified source, PGO + LTO, pip pinned |
| Node.js | 22 LTS official binary, SHA-256-verified — **`node` only, no npm** |
| Debian overlay | `libssl3`, `ca-certificates`, `tzdata` from the current security archive when distroless lags |
| User | `65532:65532`, numeric; no shell, no package manager, no SUID/SGID, runtimes root-owned |
| Size | ~115 MB |

Hardening detail, kernel/runtime controls, and the residual-risk register: [SECURITY.md](SECURITY.md).
Point-in-time audit: [SOC_AUDIT_2026-10-23.md](SOC_AUDIT_2026-10-23.md).

## Use it

```dockerfile
FROM ghcr.io/maverick-pr/aegis-hardened-base:latest AS deps
USER 0
COPY requirements.txt .
RUN pip install --no-cache-dir --target /deps -r requirements.txt

FROM ghcr.io/maverick-pr/aegis-hardened-base:latest
COPY --from=deps /deps /app/deps
COPY src/ /app/src/
ENV PYTHONPATH=/app/deps
USER 65532:65532
ENTRYPOINT ["python3", "/app/src/main.py"]
```

Run it with the shipped runtime profile (seccomp, AppArmor, no capabilities, read-only root):

```bash
docker compose up
```

Frontend builds: `npm ci && npm run build` in a `node:22` builder stage, then `COPY` only `dist/`.
The runtime image has no `npm` on purpose.

## Build it yourself (what a regulated team should do)

```bash
make build scan     # hadolint → dockle → trivy → grype; fails on any fixable CVE
make audit          # everything, nothing suppressed — for your risk register
make sbom
```

Fork, point `REGISTRY` in the Makefile and `IMAGE` in the workflow at your registry, and the same
workflow signs with *your* CI identity.

## Tags

`latest` · `YYYY-MM-DD` (weekly rebuild) · `sha-<7>` (per commit). Pin a digest in production.

## License

MIT. No warranty; see the residual-risk register before relying on it for regulated data.
