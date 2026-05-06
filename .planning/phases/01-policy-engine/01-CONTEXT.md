# Phase 1: Policy Engine - Context

**Gathered:** 2026-05-06
**Status:** Ready for planning
**Mode:** Auto-generated (discuss skipped via workflow.skip_discuss)

<domain>
## Phase Boundary

Replace YAML entitlements with Rego/OPA as the authorization backend. Every command evaluated by Rego policies before execution, with full context (user, groups, command, args, time, session ID) and audit trail. Rego evaluation result recorded in audit log. sec.* Starlark namespace exposes policy evaluation to scripts.

Requirements: POL-01, POL-02, POL-03, POL-04, POL-05, POL-06

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
All implementation choices are at Claude's discretion. Use ROADMAP phase goal, success criteria, and codebase conventions to guide decisions.

Key context:
- Current entitlements live in security/entitlements.go (YAML RBAC, per-user/group command ACL)
- BashInterceptor in security/interceptor.go is the hook point for authorization checks
- OPA Go SDK: github.com/open-policy-agent/opa
- Preferred OPA package: github.com/open-policy-agent/opa/rego or v1 API
- Default policy file path: ~/.adssh/policy.rego (or ADSSH_POLICY env var)
- YAML entitlements remain functional as a fallback migration path — Rego is the new default
- sec.* Starlark namespace lives in starlarkext/sec.go

</decisions>

<code_context>
## Existing Code Insights

Codebase context will be gathered during plan-phase research.

</code_context>

<specifics>
## Specific Ideas

- Policy evaluation context: {"user": "...", "groups": [...], "command": "...", "args": [...], "time": "...", "session_id": "..."}
- OPA eval: query "data.adssh.authz.allow" against input context
- Deny reason should be surfaced from "data.adssh.authz.deny_reason"
- Default policy (allow all) should ship so existing users are not broken
- Provide example policies: restrict sudo, allow only specific commands for group "ops"
- Migration helper: convert YAML entitlements to equivalent Rego policy

</specifics>

<deferred>
## Deferred Ideas

- Hot-reload of policy files (inotify) — nice to have, not required for v1
- Policy bundling (OPA bundles) — future enhancement
- Remote policy fetching — defer to later milestone

</deferred>
