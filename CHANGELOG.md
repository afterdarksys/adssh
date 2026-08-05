# Changelog

## Unreleased

### Added

- Added credential-shape redaction for terminal output and audit command/event/policy records.
- Added vault/cloud-backed `lease` sources for Vault, AWS Secrets Manager, Azure Key Vault, and GCP Secret Manager.
- Added session supervision metadata, audited `mirror kill`, and automatic JSONL session recording.
- Added `??` to explain the last denied command in the current session.
- Added `elevate` for time-boxed break-glass access with reason, expiry, audit events, and Rego-visible claims.
- Added `gateway start/list/stop` for policy-audited local TCP forwarding.
- Added native SSH `direct-tcpip` gateway authorization for `adssh --serve`, enabling policy-gated SSH jump traffic.
- Added structured gateway Rego input under `input.gateway`.
- Added recording manifests to evidence bundles, including recording path, size, event count, and SHA-256 digest.
- Added gateway connection evidence logs with target, duration, byte counts, close reason, and evidence-bundle digest manifests.
- Added starter policy bundles for home, regulated ops, gateway-only, and AI-agent postures.
- Added a reproducible local commercial demo script covering denied gateway access, `??`, break-glass elevation, governed gateway traffic, secret leasing, recording, and evidence export.
- Added `.adssh` line-script execution for deterministic non-interactive shell demos and runbooks, including `-`-prefixed expected-failure lines.
- Added release packaging automation for cross-platform tarballs, checksums, optional GPG checksum signatures, optional `.deb`/`.rpm` packages, and a Homebrew formula template.
- Added a GitHub Actions release workflow for version-tagged artifact builds and GitHub Release publishing.
- Added `identity` for OIDC claim import, session group mapping, local SSH CA generation, and short-lived SSH user certificate issuance.
- Added `admin` for governed local API access to sessions, gateways, pending approvals, policy explanations, and evidence export.
- Added release provenance files: `provenance.json` and `slsa-provenance.intoto.json`.
- Added structured lease Rego input under `input.lease`, lease IDs, and explicit `LEASE_REQUEST` / `LEASE_GRANT` / `LEASE_REVOKE` audit events.
- Added structured MCP agent Rego input under `input.agent`, configurable MCP agent identity, destructive-action risk classification, and `run_shell` dry-run mode.
- Added JWKS-backed OIDC JWT signature verification with issuer metadata discovery for `identity oidc import`.
- Added `admin serve` for a token-capable local HTTP API over sessions, gateways, approvals, policy explanations, and evidence bundles.
- Added `policy/bundles/admin-api.rego` for role-separated admin API access.

### Changed

- `why` and `??` share the same governance-stage explanation formatter.
- `mirror list` now reports user, principals, age, idle time, active command, recording path, active elevation, and termination state.
- Local interactive sessions are now registered with the supervision/recording layer so the commercial demo exercises the same governance evidence path without requiring `adssh --serve`.
- `why` and `??` now include prescriptive next steps for policy, RBAC, change-management, four-eyes, and restricted-mode blocks.
- `policy/bundles/ai-agent.rego` now uses MCP agent risk and dry-run context for destructive action governance.
