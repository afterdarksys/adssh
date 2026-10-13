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
- `ADSSH_SAH` is a default-off `sah/1` stdio switch. `go test -count=1 -timeout 180s ./internal/sah/ ./internal/config/ .` passed. The response field `handoff` stays `not_wired`. The provision → enroll → execute handoff is not wired.
- `identity device login` is a client of systemapi `controlplane/oauth.js`. It stores an opaque bearer in a mode `0600` file and sets the session user with no groups. Covered by `go test -count=1 -timeout 180s ./security/`.
- Admin list routes for recordings, elevations, and leases, an audit line on every non-healthz admin request, and `docs/openapi/admin.yaml`. Same `./security/` run. `GET /v1/approvals` still returns the approval token to an admin-key holder.
- Release cut procedure in `docs/release.md`, `scripts/render-homebrew-formula.sh`, and a tag-gated SLSA job pinned to `generator_generic_slsa3.yml@v2.1.0`. The formula script was run into `/tmp` and the output was deleted. The tap repository is not created. The generator is unmaintained and the build is not hermetic. No attestation is checked in.
- Lease delivery through the environment, stdin, or inherited fd 3, with `policy/examples/lease_bounds.rego`. Same `./security/` run. The evidence digest is the chain entries, computed before the lease view is attached.
- Four-eyes prompts use the public request id. `ADSSH_4EYES_WEBHOOK` can notice a new request and a policy denial of `gateway`, `lease`, or `elevate`. `??` reads `required_role`. Same `./security/` run.
- MCP tool allowlist, one session id bound at process start, and governed admin and identity tools. `go test -count=1 -timeout 180s ./cmd/adssh-mcp/` passed. `admin_*` and `identity_*` stay out of `policy/bundles/ai-agent.rego`.
- Docs site source in `docs/site/` for install, architecture, policy, gateway, leases, recordings, and MCP. It is not hosted. In-process embedding remains `docs/EMBEDDING.md`. The systemapi child path remains `docs/systemapi-embed.md`.
- Post-hardening re-review appended to `docs/SECURITY_REVIEW.md` (2026-10-12). It names the tests above. It is not a tag sign-off.

## Next Up

The items above are in the tree. Publishing is a morning step. Do not treat this list as done.

- Tag and push are not done. GPG signing needs `secrets.GPG_PRIVATE_KEY` on the Actions run. The SLSA provenance job has not run.
- The Homebrew tap repository is not created. Render the formula only from a real `SHA256SUMS`.
- `docs/site/` is source. It is not a hosted site.
- The provision → enroll → execute handoff is not wired. Do not mark it implemented.
