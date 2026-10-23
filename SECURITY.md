# Security Policy — aegis-hardened-base

## What this image is

A hardened, multi-stage-built base image providing Python 3.13 and Node.js 22 LTS,
designed for AI software delivery in regulated sectors: Healthcare (HIPAA), Banking and
Financial Services (PCI-DSS Level 1), and enterprise IT (SOC-2 Type II, ISO 27001).

---

## Hardening controls and their rationale

| Control | Implementation | Regulatory mapping |
|---|---|---|
| Immutable base | Debian bookworm-slim pinned to SHA-256 digest, not mutable tag | CIS Docker 5.25, PCI 6.3 |
| Source-verified builds | SHA-256 checked at `curl` time; build aborts on mismatch | Supply-chain: SLSA L2 |
| No build toolchain in final layer | Multi-stage — gcc/make/curl never shipped | CIS Docker 4.3 |
| No shell | Final base is distroless: no `/bin/sh`, `bash`, `dash` or busybox exist; all `/etc/passwd` shells are `/sbin/nologin` | CIS Docker 4.3, HIPAA §164.312(a) |
| No OS package manager | distroless ships no `apt`/`dpkg`. `npm`/`npx`/`corepack` are removed from the runtime; `pip` is retained for build-time use by derived images (see *Derived images*) | CIS Docker 4.3 |
| Debian security overlay | `libssl3`, `ca-certificates`, `tzdata` taken from the current Debian security archive and overlaid with their dpkg metadata when distroless lags upstream | PCI 6.3.3 |
| Non-root, numeric | `USER 65532:65532` (numeric, so K8s `runAsNonRoot` can validate), no home, no password | CIS Docker 4.1 |
| Runtime trees immutable to the workload | `/opt/python`, `/opt/node` root-owned `0755`; UID 65532 cannot modify interpreter or stdlib | PCI 2.2 / 11.5 integrity |
| No SUID/SGID files | distroless ships none; the one SGID directory (`/var/local`) is cleared at build | CIS Docker 4.8 |
| Kernel syscall filter | `seccomp-profile.json`: Docker default allow-list minus `ptrace`, `bpf`, `mount*`, `setns`, `unshare`, `perf_event_open`, `process_vm_*`, `personality`, `kcmp` | CIS Docker 5.21 |
| Mandatory access control | `apparmor:docker-default` | CIS Docker 5.1 |
| Read-only root filesystem | `read_only: true` in compose; `--read-only` at `docker run` | CIS Docker 5.12 |
| All capabilities dropped | `cap_drop: [ALL]` in compose; add back only with documented justification | CIS Docker 5.3 |
| No privilege escalation | `no-new-privileges:true` security option | CIS Docker 5.4 |
| Resource limits | CPU, memory, PID limits in compose | CIS Docker 5.28 |
| Isolated network | `internal: true` bridge; ICC disabled; no default outbound | CIS Docker 5.29 |
| Log size bounded | `max-size: 50m`, `max-file: 5` | CIS Docker 5.25 |
| OCI provenance labels | Build date, git commit, component versions on every image | SLSA L1 |
| SBOM generation | Syft produces SPDX + CycloneDX outputs at every build | EO 14028, HIPAA audit |
| CVE scan gate | Trivy + Grype block on any **fixable** finding at **any** severity (LOW included); hadolint + dockle gate Dockerfile and CIS image checks | PCI 6.3.3 |
| Full-disclosure audit | `make audit` shows every finding with no suppression, for SOC review | PCI 6.3.3, SOC-2 CC7.1 |
| Image signing | Keyless Sigstore/cosign in CI (GitHub OIDC identity, Rekor transparency log); SBOM attached as attestation; no private key exists | Supply-chain integrity, SLSA L2 |

---

## What the image cannot do: the kernel

A container shares the **host** kernel. No image content hardens it. Kernel exposure is
controlled only at runtime, and this repository ships the controls, not a promise:

| Runtime control | Where | Why |
|---|---|---|
| seccomp allow-list | `seccomp-profile.json`, wired in compose | Removes the syscalls used by every public container-escape primitive the workload has no use for |
| AppArmor `docker-default` | compose `security_opt` | Blocks `/proc`, `/sys` writes and mount tricks even if a syscall is allowed |
| `cap_drop: ALL`, `no-new-privileges` | compose | A process that starts with no capabilities cannot acquire them |
| `read_only: true` + `tmpfs noexec,nosuid` | compose | Nothing writable is executable; nothing executable is writable |
| `pids: 512`, memory/CPU limits | compose | Bounds fork-bomb and OOM-driven kernel pressure |

**Host obligations** (outside this repo): patched LTS kernel, `kernel.unprivileged_userns_clone=0`
(or user-namespace remapping enabled for the daemon), `userns-remap` or rootless Docker,
no `--privileged`, no host PID/network namespaces, Falco or equivalent syscall-level
runtime detection. In Kubernetes: Pod Security Admission `restricted` profile, which
enforces the equivalent of every row above.

---

## Accepted residual risk (register)

Reviewed on every rebuild. Anything in this table **must** also appear in `.trivyignore`
/ `.grype.yaml` with the same justification, and nothing may be suppressed that is not here.

| Component | Finding | Why accepted | Exit condition |
|---|---|---|---|
| `libssl3` (distroless) | CVE-2026-84782 HIGH + 4 MEDIUM/LOW, **no Debian fix exists** | Only patch-less OpenSSL 3.0 CVEs remain after the Debian overlay; none has a public exploit against TLS client use | Debian ships a fix → overlay picks it up automatically on rebuild |
| `libc6` 2.36 (distroless) | 23 findings, all `will_not_fix` / `fix_deferred` by Debian | glibc issues Debian has triaged as not warranting a bookworm backport; no privilege boundary crossed from a non-root, cap-less, seccomp'd process | Debian 13 rebase of distroless |
| `gcc-12-base`, `libgcc-s1`, `libgomp1`, `libstdc++6` | CVE-2026-95619, CVE-2026-102010, CVE-2022-27943 — `will_not_fix` | Compiler-runtime issues requiring attacker-supplied code to be compiled; not reachable from interpreted workloads | Debian 13 rebase |
| CPython 3.13.17 | CVE-2025-15367, CVE-2026-12345 MEDIUM, fixed only in 3.15 pre-releases | Python Security Team has not backported; 3.13 is the current security-supported line | 3.13.x release containing the backport |

Anything **not** in this table that a scanner reports is a build failure, not a judgement call.

---

## Derived images

```dockerfile
# Build dependencies in a throw-away stage; the runtime image never sees pip/npm activity
FROM aegis-hardened-base:latest AS deps
USER 0
COPY requirements.txt .
RUN pip install --no-cache-dir --target /deps -r requirements.txt

FROM aegis-hardened-base:latest
COPY --from=deps /deps /app/deps
COPY --chown=0:0 src/ /app/src/
ENV PYTHONPATH=/app/deps
USER 65532:65532
ENTRYPOINT ["python3", "/app/src/main.py"]
```

Frontend assets: run `npm ci && npm run build` in a `node:22` builder stage and `COPY` only
the `dist/` output. The runtime image deliberately has no `npm`.

---

## Obligations before using this image with real patient / financial data

1. **Run `make scan` on every build and `make audit` before every release review.** A passing scan means no *fixable* CVE at any severity at build time, with the residual-risk register above as the only exceptions. It does not mean zero CVEs tomorrow. Re-build and re-scan at least weekly; the Debian overlay stage picks up new security releases automatically.

2. **Never embed secrets in the image.** Use Docker secrets, AWS Secrets Manager, Azure Key Vault, or HashiCorp Vault. The `.dockerignore` excludes `.env*`, `*.pem`, `*.key` as a last-resort guard — do not rely on it.

3. **Pin the base digest.** Run `make repine` quarterly and whenever a Debian security advisory covers a package in the runtime set.  Review the diff before committing.

4. **Sign before you push.** CI signs every published manifest keylessly; `make sign` does the same locally. Never push an unsigned image to a production registry.

5. **Verify before you pull.** Add to every deployment pipeline before `docker pull` / `kubectl apply`:
   `cosign verify <image>@<digest> --certificate-identity-regexp '^https://github.com/maverick-pr/aegis-hardened-base/' --certificate-oidc-issuer https://token.actions.githubusercontent.com`
   (or your own fork's identity). In Kubernetes enforce it with Sigstore policy-controller or Kyverno `verifyImages`.

6. **Use runtime security contexts.** The compose file enforces `read_only`, `no-new-privileges`, `cap_drop: ALL` and resource limits. Mirror these in your Kubernetes `SecurityContext` and PodSecurityPolicy / OPA Gatekeeper rules.

7. **Audit log every image pull.** For HIPAA, your registry must log who pulled what image and when.  Use a private registry (GHCR, ECR, ACR, Artifact Registry) with pull-log retention of ≥ 6 years.

---

## Updating Python or Node.js versions

```bash
# 1. Set the new version
NEW_PY=3.13.18
NEW_NODE=22.24.0

# 2. Download and compute checksums
curl -fsSL "https://www.python.org/ftp/python/${NEW_PY}/Python-${NEW_PY}.tgz" | sha256sum
curl -fsSL "https://nodejs.org/dist/v${NEW_NODE}/node-v${NEW_NODE}-linux-x64.tar.xz" | sha256sum

# 3. Update Dockerfile ARGs (PYTHON_VERSION, PYTHON_SHA256, NODE_VERSION, NODE_SHA256)
# 4. Build and scan
make build scan

# 5. Commit only if scan passes
git add Dockerfile && git commit -m "chore: bump Python to ${NEW_PY}, Node to ${NEW_NODE}"
```

---

## Incident response

If a CVE is disclosed against a package in this image:

| Severity | Action | SLA |
|---|---|---|
| CRITICAL | Rebuild and redeploy all running containers | 4 hours |
| HIGH | Rebuild and redeploy | 24 hours |
| MEDIUM | Rebuild at next scheduled patch cycle | 7 days |
| LOW | Track; address at next version bump | Next release |

Report security issues in this repository to prabodh13@gmail.com.  Do not open a public issue for undisclosed vulnerabilities.
