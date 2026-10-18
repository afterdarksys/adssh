# Open-core split (proposed 2026-10-16)

Ryan approved: the core under Apache 2.0, the enterprise layer under BSL 1.1 in `ee/` (`ee/LICENSE`, `docs/LICENSING.md`). Until the code is split, a release cannot carry these licenses honestly, because enterprise code still lives in core packages. The split comes before v0.10.0.

## Mechanism (revised 2026-10-16, Ryan: "careful afternoon, we aren't trying to break shit")

- Enterprise source stays in its package and is named `*_ee.go` / `*_ee_test.go`, each file starting with `//go:build ee`. The n8n `.ee.` convention, in Go form. `ee/LICENSE` covers these files and everything under `ee/`.
- Separate enterprise binaries live under `ee/` (`ee/cmd/adsshadm`).
- Two builds from one tree. `go build` is the Apache core and compiles no `_ee.go` file. `go build -tags ee` is the enterprise build. Binary names stay `adssh` and `adssh-mcp`; the release script will ship enterprise tarballs separately (wave 3).
- The compiler is the guard: if core code uses anything defined in an `_ee.go` file, the core build stops compiling. CI also fails if `go list -deps` of the core binaries shows an `_ee.go` file or an `ee/` package, and it builds, vets, lints, and race-tests the `ee` variant.
- Helpers that core code shares with enterprise files live in core files (`security/shared_core.go`, `security/testhelpers_test.go`).
- Where core must call into enterprise code, core keeps a hook the `_ee.go` file fills from `init()`: `enterpriseToolRegistrars` in `cmd/adssh-mcp`. Safeguards stay in core and run in every build, e.g. `ForbidFourEyesDecisions` in the MCP server.
- Why not separate `ee/` packages: the admin code uses about 25 unexported `security` internals. Moving it out would have meant exporting them, which turns internals into public API and breaks the v0.9.0 embedder surface. With build tags, nothing is exported and no embedder API changes.
- Command names in lists (the listener Run table in `ssh_monitor.go`, `internal/sah`) do not pull code in. Turning them into registries is cleanup for a later wave, not a licensing requirement.

## Waves (adssh-06's sizing, done in a fresh session)

1. DONE on branch ee/wave1: admin API (`admin_http`, `admin_attach`, `admin_lists`, `vbin_admin`) to `_ee.go`, the MCP `admin_*` tools to `tools_admin_ee.go` via `enterpriseToolRegistrars`, adsshadm to `ee/cmd/adsshadm`, and CI for both builds. Enterprise packaging moved to wave 3.
2. DONE on branch ee/wave2 (2026-10-18): four-eyes, change management, evidence, elevate/grants, leases. Core keeps the rule and pattern readers and refuses what it cannot approve (`approval_gate.go`); the enterprise gate plugs in through `SetApprovalGate`. Gateway evidence moved with the gateway in wave 3.
3. DONE on branch ee/wave2 (2026-10-18): identity/device login, gateway, mirror_share, grid, sah, bundles (`ee/policy/bundles`), docs, and opt-in enterprise tarballs (`ENTERPRISE=1 scripts/package-release.sh`, needs `ee/LICENSE`). Not done: `internal/risk` stays core (the core REPL and the MCP `input.agent.risk` claim use it; a stub would either fail open or refuse every agent shell call). The Homebrew formula is not done.

Ryan confirmed the classification table on 2026-10-16. The refactor may start.

## Classification (confirmed 2026-10-16)

| Core: Apache 2.0 | Enterprise: `ee/`, BSL 1.1 |
|---|---|
| `engine`, `parser`, `internal/sys` (SSH server), `internal/repl`, `internal/starlarkext`, `internal/config`, `internal/i18n`, `internal/safefile`, `internal/attachproto`, `internal/guard` (SSH jail) | `security/admin_http.go`, `admin_attach.go`, `admin_lists.go`, `vbin_admin.go`, `cmd/adsshadm` |
| `security/engine.go`, `interceptor.go`, `policy.go`, `explain.go`, `vbin_why.go`, `entitlements.go`, `roles.go`, `capabilities.go` | `foureyes*.go`, `vbin_foureyes.go`, `approval_notice.go` (four-eyes) |
| `audit.go`, `audit_chain.go`, `vbin_audit.go`, `redact.go` (an SSH replacement needs a trustworthy log) | `cm.go`, `cm_hook.go`, `vbin_cm.go` (change management) |
| `plugin.go`, `openhandler.go`, `session_exec.go`, `ssh_monitor.go`, `virtualbin*.go`, `help_*.go`, `cmdgen.go`, `denial.go`, `callback_url.go` | `vbin_evidence.go`, `gateway_evidence.go` (evidence export) |
| General vbins: `nav`, `proc`, `package`, `structured`, `pick`, `par`, `stty`, `history`, `help`, `vbins`, `whoami`, `flags`, `denial`, `runtime`, `guard`, `advanced` | `vbin_elevate.go`, `grants.go` (break-glass and just-in-time roles) |
| `mirror.go` (viewing your own sessions) | `mirror_share.go` (sharing and snooping on others' sessions) |
| `cmd/adssh-mcp` (agents drive adoption) | `vbin_lease.go`, `vbin_lease_sources.go` (secret leases) |
| `policy/default.rego`, `policy/examples` | `vbin_identity.go`, `device_login.go` (OIDC import, SSH CA, device login) |
| | `vbin_gateway.go`, `gateway_policy.go` (governed gateways) |
| | `internal/grid` (fleet flights), `internal/sah` (SAH suite), `internal/risk` |
| | `policy/bundles` (regulated-ops, AI-agent, and other postures) |

Borderline rows, decided by Ryan 2026-10-16: all core. `cmd/adssh-mcp` and `internal/agent` (agents drive adoption; their governance is already enterprise), `vbin_runbook.go`, `engine_access.go`, `internal/devops`, `internal/sysmgmt`.

## Before release

1. Ryan confirms the licensor's legal name ("After Dark Systems" is what existing copyright notices use) and the US$1M threshold.
2. A lawyer reviews `ee/LICENSE`'s Additional Use Grant and `docs/LICENSING.md`.
3. Copyright ownership is settled for every contributor to the code going into `ee/`, with contributor agreements where needed.
4. The split lands, with the no-import check in CI.
5. homebrew-formula.json declares `Apache-2.0` and builds the core binary.
6. "adssh" and "sah" trademark filings are started.
