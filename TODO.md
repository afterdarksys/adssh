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
- Starter policy bundles for home, regulated ops, gateway-only, and AI-agent postures.

## Next Up

1. **Gateway Evidence Upgrade**
   - Record per-gateway connection events.
   - Include opened-by, target, start/end time, duration, byte counts, and close reason.
   - Correlate gateway sessions with audit-chain entries and evidence bundles.

2. **Commercial Demo Script**
   - Script a clean end-to-end demo:
     blocked gateway -> `??` -> `elevate` -> gateway access -> lease secret ->
     session recording -> `mirror kill` -> evidence export.
   - Use only local services where possible so the demo is reproducible.

3. **Release / Packaging**
   - GitHub release workflow.
   - Version tags.
   - Signed checksums.
   - Homebrew tap.
   - `.deb` and `.rpm` packages.

4. **SSO / SSH CA**
   - OIDC login.
   - Group mapping.
   - Short-lived SSH certificate issuance.
   - Cert principal policy examples.

5. **Admin / API Surface**
   - HTTP or MCP tools for sessions, recordings, gateways, elevations, leases,
     approvals, evidence, and policy explainability.

6. **Lease Hardening**
   - Lease IDs and explicit lease audit events.
   - Provider metadata in audit/evidence.
   - Stdin or file-descriptor injection in addition to env injection.
   - Policy examples for lease TTL/source/target restrictions.

7. **Approval UX**
   - Better user flow when gateway, lease, or elevation is blocked by CM/four-eyes.
   - Make `??` more prescriptive: required role, required approver, active ticket state.

8. **Agent Governance**
   - Per-agent identity.
   - Dry-run gates for risky tools.
   - Approval-required destructive agent actions.
   - Expanded MCP/AI-agent policy examples.

9. **Docs Site**
   - Install and packaging docs.
   - Architecture.
   - Policy authoring.
   - Gateway/bastion mode.
   - Leases.
   - Recordings/evidence.
   - MCP/agent governance.
   - Embedding.

10. **Security Review Pass**
    - Focused review of gateway, lease, recording, elevation, and evidence paths
      before tagging a release.
