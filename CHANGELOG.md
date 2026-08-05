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

### Changed

- `why` and `??` share the same governance-stage explanation formatter.
- `mirror list` now reports user, principals, age, idle time, active command, recording path, active elevation, and termination state.
