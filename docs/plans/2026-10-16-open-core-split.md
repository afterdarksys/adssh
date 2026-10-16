# Open-core split (proposed 2026-10-16)

Ryan approved: the core under Apache 2.0, the enterprise layer under BSL 1.1 in `ee/` (`ee/LICENSE`, `docs/LICENSING.md`). Until the code is split, a release cannot carry these licenses honestly, because enterprise code still lives in core packages. The split comes before v0.10.0.

## Mechanism

- Enterprise code moves into packages under `ee/` (for example `ee/admin`, `ee/foureyes`, `ee/grid`). It registers itself from `init()`, the same way the virtual binaries and the grid vbins already do.
- The core defines the hooks those packages fill: an approval gate the interceptor consults, an admin route table, and an identity provider registry. With nothing registered, the core behaves as a plain governed shell. Four-eyes and change-management checks become no-ops, and the admin API is absent.
- Two builds. `adssh` (core, Apache) does not import `ee/`. `adssh` built with the `ee` build tag, or a separate `cmd/adssh-enterprise`, blank-imports `ee/...`. Distributions ship the core build, and customers get the enterprise build.
- A CI check fails if any core package imports `ee/`.
- `ee/` lives at the repo root, not under `internal/`, so `cmd/adssh-enterprise` can import it. `ee` packages import `security`; `security` never imports `ee`.
- Every place the core lists enterprise commands by name becomes a registry the `ee` packages fill from `init()`: the listener Run table in `ssh_monitor.go`, `help_content.go`, and the REPL completer. Otherwise the core build still knows the enterprise commands exist.
- Moving exported symbols out of `security` breaks the v0.9.0 embedder API. v0.10.0 is a breaking release, and `docs/EMBEDDING.md` changes with it.
- Docs and policy follow their code into `ee/`: `policy/bundles/admin-api.rego`, `docs/openapi/admin.yaml`, and the matching parts of `docs/SECURITY_REVIEW.md`.

## Waves (adssh-06's sizing, done in a fresh session)

1. Hooks: an admin route registry and an identity registry next to the existing `cm_hook.go` and `foureyes_hook.go` seams, plus the core-never-imports-ee CI check. Then move admin, attach, and adsshadm.
2. Four-eyes, change management, evidence, elevate/grants, leases.
3. Identity/device login, gateway, mirror_share, grid, sah, risk, bundles, docs, release.

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
