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

## Next Up

1. **SSO / SSH CA**
   - OIDC login.
   - Group mapping.
   - Short-lived SSH certificate issuance.
   - Cert principal policy examples.

2. **Admin / API Surface**
   - HTTP or MCP tools for sessions, recordings, gateways, elevations, leases,
     approvals, evidence, and policy explainability.

3. **Release Hardening**
   - Publish a dedicated Homebrew tap repository.
   - Add release provenance/SLSA attestation.
   - Document GPG signing key setup and release cut procedure.

4. **Lease Hardening**
   - Lease IDs and explicit lease audit events.
   - Provider metadata in audit/evidence.
   - Stdin or file-descriptor injection in addition to env injection.
   - Policy examples for lease TTL/source/target restrictions.

5. **Approval UX**
   - Better user flow when gateway, lease, or elevation is blocked by CM/four-eyes.
   - Make `??` more prescriptive: required role, required approver, active ticket state.

6. **Agent Governance**
   - Per-agent identity.
   - Dry-run gates for risky tools.
   - Approval-required destructive agent actions.
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
