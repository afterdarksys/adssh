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

## Next Up

1. **Identity Hardening**
   - Full OIDC authorization-code/device login flow.
   - Cert principal policy examples.

2. **Admin API Hardening**
   - Extend HTTP API coverage to recordings, elevations, leases, and approval actions.
   - MCP parity for the new `admin` and `identity` operations.
   - HTTP API audit event details and OpenAPI schema.

3. **Release Hardening**
   - Publish a dedicated Homebrew tap repository.
   - Document GPG signing key setup and release cut procedure.
   - Add signed SLSA provenance through GitHub OIDC/keyless signing.

4. **Lease Hardening**
   - Provider metadata in evidence bundles.
   - Stdin or file-descriptor injection in addition to env injection.
   - More policy examples for lease TTL/source/target restrictions.

5. **Approval UX**
   - Show active pending token and required approver directly in denial output.
   - Add optional webhook-driven approval links for gateway, lease, and elevation blocks.
   - Make `??` infer required role from structured policy metadata where available.

6. **Agent Governance**
   - Approval-required destructive agent actions.
   - Agent-specific entitlements and session binding.
   - Expanded MCP/AI-agent policy examples.

7. **Docs Site**
   - Install and packaging docs.
   - Architecture.
   - Policy authoring.
   - Gateway/bastion mode.
   - Leases.
   - Recordings/evidence.
   - MCP/agent governance.
   - Embedding.

8. **Security Review Pass**
    - Focused review of gateway, lease, recording, elevation, and evidence paths
      before tagging a release.
