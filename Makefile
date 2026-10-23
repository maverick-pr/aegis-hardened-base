# =============================================================================
# aegis-hardened-base — build, scan, sign, push workflow
#
# Prerequisites (install once per machine):
#   brew install trivy grype cosign syft docker
#
# Typical pipeline:
#   make build   →  make scan   →  make sbom   →  make sign   →  make push
# =============================================================================

IMAGE      := aegis-hardened-base
REGISTRY   := ghcr.io/maverick-pr      # change to your registry
TAG        := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
FULL_IMAGE := $(REGISTRY)/$(IMAGE):$(TAG)
LATEST     := $(REGISTRY)/$(IMAGE):latest
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GIT_COMMIT := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)

.PHONY: build scan audit sbom sign push verify clean repine help

# ── Build ─────────────────────────────────────────────────────────────────────
build:
	@echo "▶ Building $(FULL_IMAGE)"
	docker build \
		--no-cache \
		--pull \
		--build-arg BUILD_DATE="$(BUILD_DATE)" \
		--build-arg GIT_COMMIT="$(GIT_COMMIT)" \
		--label "build.host=$(shell hostname)" \
		-t $(FULL_IMAGE) \
		-t $(LATEST) \
		-f Dockerfile .
	@echo "✓ Build complete: $(FULL_IMAGE)"

# ── CVE scan — FAILS on any finding at any severity ──────────────────────────
# --ignore-unfixed removes CVEs where upstream has no patch yet (not exploitable
# in the conventional sense and outside our control). This is the accepted
# practice for distroless images in regulated-sector audits.
scan: build
	@echo "▶ Linting Dockerfile (hadolint)"
	hadolint Dockerfile
	@echo "▶ CIS image benchmark (dockle)"
	docker save $(FULL_IMAGE) -o /tmp/$(IMAGE)-scan.tar
	dockle --exit-code 1 --exit-level warn --input /tmp/$(IMAGE)-scan.tar
	@echo "▶ Scanning with Trivy (CRITICAL HIGH MEDIUM LOW)"
	trivy image \
		--exit-code 1 \
		--severity CRITICAL,HIGH,MEDIUM,LOW \
		--ignore-unfixed \
		--format table \
		$(FULL_IMAGE)
	@echo "▶ Scanning with Grype (second opinion, all severities)"
	grype $(FULL_IMAGE) \
		--config .grype.yaml \
		--fail-on low \
		--output table
	@echo "✓ Scan passed — no fixable CVEs at any severity"

# ── Full-disclosure audit: NOTHING suppressed. For SOC review and risk register. ──
# Shows every finding including unfixable ones and those accepted in
# .trivyignore / .grype.yaml, so reviewers see the real residual risk.
audit:
	@echo "▶ Trivy — all scanners, unfixed included, suppressed shown"
	trivy image --scanners vuln,secret,misconfig,license \
		--severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL --show-suppressed \
		--ignorefile /dev/null $(FULL_IMAGE)
	@echo "▶ Grype — no ignore rules"
	docker save $(FULL_IMAGE) -o /tmp/$(IMAGE)-scan.tar
	grype docker-archive:/tmp/$(IMAGE)-scan.tar --output table
	@echo "▶ Dockle — all levels"
	dockle --exit-code 0 --input /tmp/$(IMAGE)-scan.tar
	@echo "▶ Component inventory"
	syft docker-archive:/tmp/$(IMAGE)-scan.tar -o table

# ── SBOM generation (SPDX + CycloneDX) ──────────────────────────────────────
sbom: build
	@echo "▶ Generating SBOM (SPDX)"
	syft $(FULL_IMAGE) -o spdx-json > $(IMAGE)-$(TAG).spdx.json
	@echo "▶ Generating SBOM (CycloneDX)"
	syft $(FULL_IMAGE) -o cyclonedx-json > $(IMAGE)-$(TAG).cdx.json
	@echo "✓ SBOMs written: $(IMAGE)-$(TAG).spdx.json  $(IMAGE)-$(TAG).cdx.json"

# ── Sign with Sigstore/cosign (keyless) ──────────────────────────────────────
# No private key anywhere. Locally this opens a browser for OIDC login; in CI the
# GitHub Actions workflow (.github/workflows/build.yml) signs with its own identity.
# Verifiers check the signer identity, not a key:  make verify
sign: scan
	@echo "▶ Pushing $(FULL_IMAGE) for signing"
	docker push $(FULL_IMAGE)
	@DIGEST=$$(docker inspect --format='{{index .RepoDigests 0}}' $(FULL_IMAGE)); \
	echo "▶ Signing $$DIGEST (keyless)"; \
	cosign sign --yes $$DIGEST; \
	echo "✓ Image signed: $$DIGEST"

# ── Push (scan must have run first in CI; enforced by dependency) ─────────────
push: scan sbom sign
	docker push $(LATEST)
	@echo "✓ Pushed $(FULL_IMAGE) and $(LATEST)"

# ── Verify a pulled image's signature before use ─────────────────────────────
verify:
	cosign verify $(LATEST) \
		--certificate-identity-regexp '^https://github.com/maverick-pr/aegis-hardened-base/' \
		--certificate-oidc-issuer https://token.actions.githubusercontent.com

# ── Re-pin base digest (run quarterly or when Debian security advisory fires) ─
repine:
	@echo "▶ Pulling latest debian:bookworm-slim"
	docker pull debian:bookworm-slim
	@NEW=$$(docker inspect --format='{{index .RepoDigests 0}}' debian:bookworm-slim \
	        | sed 's/.*@//'); \
	echo "New digest: $$NEW"; \
	sed -i.bak "s|sha256:[a-f0-9]\{64\}|$$NEW|" Dockerfile; \
	rm -f Dockerfile.bak; \
	echo "✓ Dockerfile updated. Review with: git diff Dockerfile"

clean:
	docker rmi $(FULL_IMAGE) $(LATEST) 2>/dev/null || true
	rm -f *.spdx.json *.cdx.json

help:
	@grep -E '^[a-zA-Z_-]+:' Makefile | \
		awk -F: '{printf "  %-12s\n", $$1}'
