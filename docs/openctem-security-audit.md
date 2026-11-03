# OpenCTEM v0.16.1 — security audit of the reference checkout

Date: 2026-10-30. Target: the deployed checkout at `/Volumes/980PRO/Workspace/Councilbox/CYB/openctem`, tag `v0.16.1` (commit `a3ab8af`). Purpose: prove the reference code is safe to study (and its patterns safe to port) before building our clean-room clone. The checkout itself is READ-ONLY; nothing in it was modified.

## Verdict

No malicious code, no backdoors, no exfiltration paths, no runtime code fetch, no suspicious dependencies. The supply chain is pinned far above industry norm. Safe as a reference for reading and clean-room porting. Minor hygiene findings below (dev-tooling pinning, one un-pinned observability stack, and local untracked credential residue in the checkout directory).

## 1. Provenance — verified

- `git ls-remote https://github.com/openctemio/openctem.git v0.16.1` → `refs/tags/v0.16.1^{commit}` is `a3ab8af4b13f741fc920bd58b5951ae11dc1e8e1`, exactly the local HEAD. The tree is authentic upstream v0.16.1, not a forged local clone.
- Git tags are not GPG-signed; upstream integrity is instead enforced by release images (cosign + signed SPDX SBOM + SLSA provenance per the README) and by repo CI: every one of 315 `uses:` in `.github/workflows` is pinned to a full 40-hex action SHA, enforced by `.github/scripts/check-action-pins.sh` and a `security_gate.py` rule.
- Working tree clean except two untracked files produced by *our* local deployment run: `api/deploy/bootstrap-admin-{output,err}.txt` — see hygiene findings.

## 2. Go API (`api/`, ~6,500 Go files, 142 domain packages) — clean

Verified directly (own greps): **zero** `os/exec` imports in non-test code (exec appears only in 6 `*_test.go` files), **zero** `replace` directives in `go.mod`, all Dockerfile bases official and digest-pinned (`golang:1.27.3-alpine@sha256:…`, `distroless/static-debian13:nonroot@sha256:…`).

Full findings (static pass over go.mod, internal/, pkg/, cmd/, Dockerfiles):

- `go.mod` dependencies are the standard enterprise stack (chi, asynq, redis, lib/pq, golang-jwt, AWS SDK v2, go-git, gorilla/websocket, prometheus, OpenTelemetry, sigstore-go, crewjam/saml, go-webauthn). The only non-standard path is the first-party `github.com/openctemio/ctis` shared-types module, imported exactly where the contract is used.
- No `unsafe` (grep hits are string constants like `KindUnsafe`), no cgo (`CGO_ENABLED=0` builds).
- Every hardcoded `http(s)://` host is explainable: OIDC issuer allowlists (microsoft/google), SCM providers (github/gitlab/bitbucket), notifier platforms (telegram/teams/splunk), CVE/EPSS/CT feeds, test fixtures (`*.example`/`*.test`/`evil.*`). No odd TLDs, no raw-IP beacons, no onions.
- Raw IPs in `pkg/domain/proxypool/pool.go` (`100.100.100.200`, `168.63.129.16`, `fd00:ec2::254`) are a cloud-metadata SSRF **deny list** — hardening against dialing EC2/Azure/Alibaba metadata services, the opposite of an exfil channel.
- `init()` in `internal/infra/fetchers/git_snapshot.go` *replaces* go-git's default transports with an SSRF-guarded client and strips `ssh/git/file` transports so the API server cannot even read its own disk through a git URL — hardening.
- All 22 background tickers live in expected infra (schedulers, liveness, rate limiters, redis metrics, signer keyset rotation). No ticker-driven network beacon pattern.
- All 41 non-test base64/hex decode sites are crypto/token code (SAML/OIDC/JWKS, webhook signatures, sealed sensor payloads, job/feed signing). No rot13/xor de-obfuscation of opaque blobs.
- No hardcoded credentials: `AKIA…`/`octs_` hits are an example-value *leak detector* string, sensor config templates with placeholders, and the product's own sensor-key format logic. No PEM literals outside intended parsers, no default passwords in configs (compose fails closed via `:?` on required secrets).
- Filesystem effects confined to documented data/signer/attachments paths; `/etc/passwd`-style strings are blocked-path deny lists for templates/ingest; no `~/.ssh`; no fsnotify.
- Runtime images are distroless, non-root, read-only binaries; writable only `data/` and `signer/`. go.sum verification enforced; no GOPRIVATE/GONOSUM bypass.

## 3. Next.js web + platform console (`web/`, `web/console`) — clean (verified directly)

- **Supply chain:** 1,168 packages in `package-lock.json` with **zero** lifecycle scripts (no `preinstall`/`postinstall`/`prepare` anywhere in the lock) — the classic npm supply-chain vector is absent. The 86 direct dependencies are all standard, recognizable ecosystem packages (Radix UI family, TanStack table, react-hook-form, zustand, swr, recharts, Sentry, Playwright, vitest); no typosquats or one-off obscure packages.
- **Hardcoded hosts in src/scripts/config:** all explainable — `example.com`/`*.example`/`*.test`/`evil.*` test fixtures, github.com + release-assets.githubusercontent.com, docs.openctem.io, gitlab.com, nvd.nist.gov, owasp.org, cwe.mitre.org, `token.actions.githubusercontent.com` (Sigstore doc references), localhost/127.0.0.1.
- **Behavior files reviewed:** `src/proxy.ts` (Next 16 middleware) implements route protection by cookie *shape only* (no network call, API validates every request server-side), locale detection, CSP with fresh script nonce, legacy invitation redirect, and CSRF double-submit rejection for Server Actions — defensiveness, not attack surface. `next.config.ts`, `instrumentation.ts` and `server-with-ws.mjs` (108–142 lines each) contain no unexpected fetch/exec/eval beyond the filtered legit references (Sentry, nextjs docs). All other top-level behavior hooks were scanned for network primitives with nothing outside the allowlist domains.

## 4. Deploy, CI workflows, hooks, scripts, containers — clean

- **Workflows:** all 315 `uses:` SHA-pinned (CI-enforced). `pull_request_target`/`issue_comment` workflows never check out or execute PR code; the security gate checks out its gate script + path list from the **base SHA**. Every `curl` download fetches a release tarball from github.com and SHA-256-verifies it — no `curl | bash` anywhere. No artifacts uploaded off GitHub; no secrets interpolated into shell lines; logins via `--password-stdin`; `persist-credentials: false` widespread; `write-all` token banned by the security gate. Self-hosted runners are opt-in via repo variables, and fork PRs are forced to hosted labels.
- **Containers:** every concrete `FROM` is registry+tag+`@sha256` digest; no `ADD` of remote artifacts at all; Caddy built from pinned module versions through the Go module proxy with checksum DB verification; all-in-one assembles from per-component release images, one uid per process, root-readonly code dir, no network fetches in supervisor/healthcheck/entrypoints (health checks hit 127.0.0.1 only).
- **Compose (`api/deploy/docker-compose.yml`, 758 lines):** only the gateway publishes a port; everything else internal; `cap_drop: ALL` with narrow additions, `no-new-privileges` + `read_only` defaults, TLS between datastores, **no** docker.sock, no privileged/pid:host anywhere in the app deploy.
- **Runtime payload:** migrate/seed containers are COPY-only and execute repo-bundled SQL/binaries; verified nothing in deploy/, api/deploy/ or scripts/ downloads code at runtime from any non-registry, non-openctem host.
- **Airgap path:** release fetch/mirror scripts require a Sigstore bundle tied to `tag` OIDC issuer, files match line-by-line, images cosign-verified at source and destination digests; egress allowlist templates included.
- **Secrets:** `setup.sh` generates secrets locally into `.env` (0600); `.env.example` ships only placeholder expressions; `.githooks` read in full — no network, no fetch-and-exec; signing tooling generates ed25519 keys 0600/0700, refuses overwrite, never prints private material.

## 5. Hygiene findings (none are verdict-breaking)

1. **Un-pinned observability stack** (`deploy/observability/docker-compose.yml`): third-party exporter images use floating tags (`prom/prometheus:v3.15.0`, `grafana:13.2.3`, …) without digest pins, unlike all first-party images. Mitigated by no published ports + no-new-privileges + read-only FS; still the weakest pinning in the tree. (`cadvisor` read-only docker socket and `node-exporter` pid:host here are standard container-metrics tradeoffs, isolated to the observability network.)
2. **Dev-machine Makefile targets** (`api/Makefile`): `go install` of staticcheck/air/mockgen at `@latest` and `hadolint`/a trivy apt-key `wget` without checksum — dev-only targets, not in build or CI gates.
3. **Local credential residue (ours, not upstream's):** untracked `api/deploy/bootstrap-admin-output.txt` + `bootstrap-admin-err.txt` in the checkout directory contain the temporary local dev admin credentials printed once by the bootstrap container. Upstream uses a throwaway, read-only, no-logging `tools` profile for that step — the leak is purely our local file sitting un-gitignored in a writable directory. Recommended: delete the two files and add them (or `.well-known` pattern) to `api/deploy/.gitignore` for local peace of mind. Our locally generated `.env` and `ca/` are already gitignored.

## Conclusions for the clone

- The reference behavior is reproducible by reading only — nothing about the deployment or the code hides execution we could not see.
- Their supply-chain discipline (SHA-pinned actions, digest-pinned images, verified downloads, zero npm lifecycle scripts, sigstore-verified feeds) is explicitly worth *porting as concept* into our Python/JS clone: pin everything, verify everything, fetch-and-verify instead of curl-pipe.
- Their defensive app patterns worth mirroring are listed in `docs/openctem-data-model.md` (fingerprinting, evidence redaction, audit chain) — none require their code, only their ideas.
