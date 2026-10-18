# Changelog

## v0.10.0 (2026-10-18)

The first tagged release since v0.9.0 (70 commits). It is a breaking release for embedders and for anyone who built from the default branch.

### Breaking

- adssh is now open core. The core is Apache 2.0 (`LICENSE`); the enterprise layer is BSL 1.1 (`ee/LICENSE`, `docs/LICENSING.md`). `go build` produces the core; `go build -tags ee` produces the enterprise build. Every `*_ee.go` file and everything under `ee/` is enterprise.
- The core build drops the enterprise API listed in `docs/EMBEDDING.md` §7: the admin API and `adsshadm`, four-eyes approvals, change management, evidence export, `elevate` and grants, secret leases, `identity` (OIDC import, device login, SSH CA), governed gateways and SSH `direct-tcpip`, mirror sharing and supervision of other users' sessions, `internal/grid`, `internal/sah`, and the policy bundles (now `ee/policy/bundles`). The command names stay reserved in the core build and never fall through to a program of the same name on `PATH`.
- The core build refuses any command that a four-eyes rule or strict change management (`ADSSH_CM_STRICT=1` with `ADSSH_CM_PATTERNS`) covers, because it cannot approve it. An unreadable four-eyes rules file refuses every command in both builds; it used to read as no rules.
- `authorized_keys` lines need `user="name"`.
- `identity oidc import` takes the issuer, JWKS URL and audience from `ADSSH_OIDC_*` only; `identity device login` needs `ADSSH_CONTROLPLANE_URL`; `ADSSH_AUDIT_URL` must be https; approvals need a named key from `ADSSH_ADMIN_KEYS` (the legacy `ADSSH_ADMIN_API_KEY` can only read).
- `RLIMIT_NPROC` and `RLIMIT_AS` are off by default for SSH sessions (`ADSSH_SESSION_NOFILE`, `ADSSH_SESSION_FSIZE` and `ADSSH_SESSION_CPU_SECONDS` remain; `0` leaves a limit alone).

### Security

- Each SSH login runs in its own process, started by the listener as the login user, and fails closed when the audit log cannot be written.
- SSH listener logging levels (`ADSSH_LOG_LEVEL`, `ADSSH_LOG_FORMAT`) and `SSH_LOGIN_OK`, `SSH_LOGIN_FAIL`, `SSH_SESSION_START` and `SSH_SESSION_END` audit records; audit values are percent-encoded so redaction cannot swallow quotes.
- SSH certificate and key revocation through `ADSSH_REVOKED_KEYS` (fingerprints including the CA, `serial:N`, `keyid:ID`), reloaded on change, fail closed. A global login-failure cap and IPv6 /64 grouping for probes.
- SSH session caps (`ADSSH_MAX_SESSIONS`), signal dispositions restored before session limits apply, and an SSH listener jail (`docs/guard.md`).
- Session identity is bound to the authenticated login; network redirects are gated; identity providers are pinned.
- Starlark and policy bypasses closed: namespaces locked, set literals and unfinished blocks routed through the gate, exec error controls stripped, checked plugins loaded only when the operator asks.
- Capability-group policy: `security/capabilities.go` classifies each command into `input.capabilities` for Rego, with a fail-closed `unclassified` tag.
- Secure process execution rework for Starlark: a shared gated core, a per-session engine, timeouts and capped output, failing closed.
- The 2026-10-16 security review and remediation are recorded in `docs/reviews/`; findings R1-R6 from the secure-beta review are tracked in `docs/plans/2026-10-16-secure-beta.md`.

### Added (since the July cut)

- `adssh --serve` as an SSH server with client terminal modes, exit status after output, client locale, and a no-terminal service loop; `ADSSH_ADMIN_LISTEN` for serve mode.
- `adsshadm` (enterprise), an admin CLI for the local admin API, including `snoop` to attach to a session over `adssh-attach/1` framing (`internal/attachproto`).
- PTY-backed foreground exec for full-screen programs; multiline pastes are held until the operator runs them; the git branch in the prompt when enabled; shell `if`, `else` and `try` blocks on exit status; history suggestions are display only.
- `sys.parallel` for gated command strings across hosts, with isolated copies of session globals; the grid moved to `internal/grid` (enterprise); a `config` stdlib; `str`, `fs` read and tests, and `re` Starlark builtins; YAML and struct-shaped JSON in data pipelines; governed `fs.write`; the instrumentation-agent HTTP listener.
- `man adssh` and help topics; the default `.adsshrc` loads without error.
- Release signing: the public key in `KEYS`, `SHA256SUMS` signed in the release workflow when `GPG_PRIVATE_KEY` is set, GitHub build-provenance attestations for every file in `dist/`, and `homebrew-formula.json` for the core formula. Enterprise tarballs (`adssh-enterprise_*`) are built only with `ENTERPRISE=1` and an `ee/LICENSE` present.

### Added (July 2026 governance work)

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
- Added JWKS-backed OIDC JWT signature verification for `identity oidc import`. The issuer, JWKS URL and audience are pinned in `ADSSH_OIDC_*` configuration; the import never takes them from the command line.
- Added `admin serve` for a token-capable local HTTP API over sessions, gateways, approvals, policy explanations, and evidence bundles.
- Added `policy/bundles/admin-api.rego` for role-separated admin API access.

### Changed

- `why` and `??` share the same governance-stage explanation formatter.
- `mirror list` now reports user, principals, age, idle time, active command, recording path, active elevation, and termination state.
- Local interactive sessions are now registered with the supervision/recording layer so the commercial demo exercises the same governance evidence path without requiring `adssh --serve`.
- `why` and `??` now include prescriptive next steps for policy, RBAC, change-management, four-eyes, and restricted-mode blocks.
- `policy/bundles/ai-agent.rego` now uses MCP agent risk and dry-run context for destructive action governance.
