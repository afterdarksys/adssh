# TODO

Current product direction: Tectia-style secure access plus CyberArk-style privileged
control, with a programmable and AI-native operations shell.

## Recently Completed

- Vault/cloud-backed one-command secret leases.
- Credential redaction across leased output and audit command/event/policy records.
- Live session supervision with `mirror list/view/console/kill`.
- JSONL session recording with recording manifests in evidence bundles.
- `??` last-denial explainability.
- `elevate` JIT/break-glass elevation with Rego-visible claims.
- Policy-audited local TCP gateway via `gateway start/list/stop`.
- Native SSH `direct-tcpip` gateway authorization for `adssh --serve`.
- Structured gateway policy input under `input.gateway`.
- Gateway connection evidence with byte counts and evidence-bundle digest manifests.
- Starter policy bundles for home, regulated ops, gateway-only, and AI-agent postures.
- Reproducible local commercial demo script for the governed-access story.
- Release packaging script and GitHub release workflow for tarballs, checksums,
  optional signed checksums, optional `.deb`/`.rpm`, and Homebrew formula metadata.
- OIDC claim import, session group mapping, local SSH CA generation, and
  short-lived SSH user certificate issuance.
- Governed local `admin` API for sessions, gateways, approvals, explanations,
  and evidence export.
- Release provenance and SLSA-style attestation metadata.
- Prescriptive `why` / `??` next-step guidance for blocked commands.
- Lease IDs, structured `input.lease` policy context, and explicit lease
  request/grant/revoke audit events.
- MCP agent identity, structured `input.agent` policy context, destructive-risk
  classification, and `run_shell` dry-run mode.
- JWKS-backed OIDC signature verification with issuer discovery.
- Token-capable local `admin serve` HTTP API for sessions, gateways, approvals,
  explanations, and evidence.
- Role-separated `admin-api.rego` starter policy bundle.
- Admin HTTP refuses an empty API key. Comparison hashes both sides with SHA-256, then compares the digests. `POST /v1/approvals/approve` and `POST /v1/approvals/deny` exist. `GET /v1/approvals` lists the handler's engine.
- Four-eyes denial and timeout name the required approver. `DenyRequestAs` rejects a bad token, an empty approver, self-deny, and a caller who is not the configured approver. The pending file stays until a matching deny.
- Starlark `http_get`, `tcp_send`, and `dial_tls` refuse `skip_verify` before any dial and set TLS 1.3 as the minimum. `ADSSH_ALLOW_INSECURE_TLS` is not read.
- `Session.RunShell` runs `GateProgram` before `Runner.Run`. `RunStarlark` executes on the session thread.
- Policy examples `policy/examples/cert_principal.rego`, `lease_bounds.rego`, and `agent-destructive.rego`.
- `docs/systemapi-embed.md` for the out-of-process systemapi break-glass path. In-process hosts stay on `docs/EMBEDDING.md`.
- Defensive review in `docs/SECURITY_REVIEW.md` (2026-10-12). It is not a release sign-off.

## Next Up

1. **Identity Hardening**
   - The systemapi control plane has username-first device login. adssh still imports OIDC JWTs and does not run that flow. Certificate principals are already session principals and are evaluated as `input.groups`. The example is `policy/examples/cert_principal.rego`.

2. **Admin API Hardening**
   - Approve and deny HTTP actions are done. Recordings, elevations, and leases still have no list store.
   - MCP parity for the new `admin` and `identity` operations.
   - HTTP API audit event details and OpenAPI schema.

3. **Release Hardening**
   - Publish a dedicated Homebrew tap repository.
   - Document GPG signing key setup and release cut procedure.
   - Add signed SLSA provenance through GitHub OIDC/keyless signing.

4. **Lease Hardening**
   - Provider metadata in evidence bundles.
   - Stdin or file-descriptor injection in addition to env injection.
   - TTL, source, and destination example: `policy/examples/lease_bounds.rego`.

5. **Approval UX**
   - Denial and timeout errors name the required approver. The pending request still prints the token to the operator who asked.
   - Add optional webhook-driven approval links for gateway, lease, and elevation blocks.
   - Make `??` infer required role from structured policy metadata where available.

6. **Agent Governance**
   - Approval-required destructive agent actions. `policy/bundles/ai-agent.rego` already denies a destructive MCP call unless `dry_run` is set or a human-approved elevation is present. `policy/examples/agent-destructive.rego` is the short form of that rule.
   - Agent-specific entitlements and session binding.

7. **Docs Site**
   - Install and packaging docs.
   - Architecture.
   - Policy authoring.
   - Gateway/bastion mode.
   - Leases.
   - Recordings/evidence.
   - MCP/agent governance.
   - In-process embedding is `docs/EMBEDDING.md`. The systemapi out-of-process path is `docs/systemapi-embed.md`. A public docs site is still not built.

8. **Security Review Pass**
   - Written in `docs/SECURITY_REVIEW.md`. Re-review gateway, lease, recording, elevation, and evidence before tagging a release. The 2026-10-12 note is not that sign-off.
