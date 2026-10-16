# Provision → enroll → execute: the adssh side

Status: DESIGN, 2026-10-16. Not wired. The suite contract
(`~/development/systemapi.io/docs/sah-suite.md`, "Not wired") says this handoff ships only
with a test in each caller and callee and an edit to the Wired join list there. This file is
the adssh half of that change, written so the systemapi and computeapi halves can be designed
against it. Nothing in `adssh sah` changes until all three land together.

## What exists

- `ADSSH_SAH=1 adssh sah` reads one `sah/1` frame from stdin. `hello` answers; `execute`
  runs `command[]` with `exec`, no shell, after a loaded policy allows it (`policy_required`
  otherwise). The frame's `lease_id` is carried and ignored. `handoff` is `not_wired`.
- systemapi issues control-plane leases for the agent PTY path (`terminal:open`,
  `breakglass:open`) and checks them server-side. The agent never hands a lease to adssh;
  break-glass starts `adssh` as a child with an allow-all policy and relies on the lease
  having been checked before the PTY started.
- computeapi provisions machines (Vast.ai, io.net today) and does not enroll them anywhere.

## The gap

An `execute` frame is trusted because the caller is trusted (it is local stdin). There is no
way for a remote control plane to say "this command, on this host, for this principal, until
this time" that adssh can verify on its own. That statement is the lease.

## Lease format (proposal for systemapi to issue)

A compact signed token, Ed25519 (SECURITY-RULES rule 4), issued by systemapi, carried in the
`execute` frame as `lease`:

```json
{
  "v": 1,
  "iss": "https://systemapi.io",
  "kid": "sahlease-2026-10",
  "sub": "user:alice",                 // principal, as systemapi names it
  "host": "h_01J9...",                 // systemapi host_id of the machine this runs on
  "scope": "exec",
  "cmd": ["systemctl", "restart", "nginx"],   // exact argv, or
  "cmd_prefix": ["kubectl", "get"],           // an allowed prefix (one of the two)
  "iat": 1760600000, "nbf": 1760600000, "exp": 1760600300,   // ≤ 300 s lifetime
  "jti": "L-7c2e..."                   // single use
}
```

Encoding: JSON header `{"alg":"EdDSA","kid":...}` + payload + signature, base64url, like a
JWT but with the algorithm pinned at verification, not read from the header.

## What adssh checks before policy

1. `lease` present when `ADSSH_SAH_REQUIRE_LEASE=1` (default on once wired); absent → `lease_required`.
2. Signature verifies against the systemapi public key pinned in `ADSSH_SAH_LEASE_KEYS`
   (a 0600 file of `kid=ed25519:<base64>` lines; no network key fetch). Unknown `kid` → `lease_rejected`.
3. `iss` equals the configured issuer; `host` equals this machine's enrolled `host_id`
   (`ADSSH_SAH_HOST_ID`, written by the enrollment step); `nbf ≤ now < exp`; `exp − iat ≤ 300`.
4. `jti` not seen before: a small on-disk set under the state dir, pruned at `exp`.
5. `cmd` equals the frame's `command[]` exactly, or `cmd_prefix` is a prefix of it.
6. Then the existing path: policy (`input.lease` carries `sub`, `host`, `jti`, `exp`),
   change management, four-eyes, audit. The lease authorizes nothing by itself; it is a
   necessary condition the policy can also read.

Every rejection is a fixed code (`lease_required`, `lease_rejected`, `lease_expired`,
`lease_replayed`, `lease_command_mismatch`) and an audit event with the `jti` and the
SHA-256 fingerprint of the token, never the token.

Threats: a stolen token is bounded to one host, one command shape, five minutes and one use;
a stolen signing key is systemapi's incident and is rotated by `kid`; replay is stopped by
`jti`; a compromised machine can still run anything it likes as itself — the lease governs
what the control plane will vouch for, not what root can do locally.

## Enrollment (the piece that is nobody's yet)

computeapi provisions → cloud-init on the new machine runs `systemapi-agent enroll` with a
one-time enrollment token from computeapi's job → systemapi records the host, hands back
`host_id` and the current lease `kid`/public key → the agent writes
`ADSSH_SAH_HOST_ID` and `ADSSH_SAH_LEASE_KEYS` into adssh's state dir (0600) → from then
on `sahconnect`/the control plane can send `execute` frames with leases.

Tests that make it "wired" (one per repo): adssh refuses an `execute` without a lease,
with a tampered, expired, wrong-host, wrong-command or replayed lease, and runs with a valid
one (`internal/sah` + root package); systemapi issues a lease only for an enrolled host and a
principal with the scope; computeapi's provisioning job emits the enrollment token and the
machine appears in systemapi.

## Decisions needed from the operator

- Lease carrier: a new field on the `sah/1` frame (above) or a `sah/2` frame version.
- Key distribution at enrollment vs. a pinned long-lived systemapi key baked into images.
- Whether `cmd_prefix` is allowed at all in the first version (exact `cmd` only is safer).
