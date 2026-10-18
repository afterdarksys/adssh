# Policy authoring

Policies are Rego. The engine queries `data.adssh.authz`. A loaded policy that errors, omits `allow`, or returns a non-bool `allow` denies. No policy loaded allows, unless `RequirePolicy` refused to construct the engine.

Start from deny:

```rego
package adssh.authz

default allow = false
```

## Decision fields

The engine reads these fields from `data.adssh.authz`:

| Field | Type | Meaning |
|---|---|---|
| `allow` | bool, required | Only `allow == true` permits. Missing or non-bool denies. |
| `deny_reason` | string | Shown to the operator and written to the audit log. |
| `required_role` | string | The role that would allow it. `??` suggests `elevate request <role>`. |
| `rule` | string | A short name for the rule that decided. |
| `required_entitlement` | string | The entitlement that would allow it. |

`rule` and `required_entitlement` are optional. When present, each must be a string. Any other value (a number, an object, a partial set) denies the command with `policy: non-string rule` or `policy: non-string required_entitlement`. A policy that sets neither behaves as before.

`why`, `??`, `admin explain`, and `POST /v1/explain` return `rule` and `required_entitlement` with the decision. They also list `held_entitlements` (the RBAC entries the session holds, as `user:<name>` and `group:<name>`) and `needed_entitlements` (the policy's `required_entitlement`, then the RBAC entries that list the command) when the command is denied. The `[POLICY]` audit line gains `rule="..." required_entitlement="..."` when either is set, and the audit chain entry carries the same text in its reason. A decision without them writes the same line as before.

`EvaluatePolicyDecision` returns all five fields. `EvaluatePolicy` still returns `(allowed, reason, error)`.

`policy/examples/explained.rego` sets every field.

```rego
package adssh.authz

import future.keywords.in

default allow = false
default rule = "default_deny"

rule = "k8s_write" {
    input.command == "kubectl"
}

required_entitlement = "k8s-write" {
    input.command == "kubectl"
    not "k8s-ops" in input.groups
}
```

## What this session may do

`whoami` prints only the session user, like the OS binary, so `$(whoami)` keeps working. `whoami -v` prints the user, principals, identity source, elevation, and agent claim. `whoami --caps` adds the RBAC entries the session holds, the commands they list, and the `ExplainCommand` outcome of a fixed list of representative commands and one governed Starlark path per capability group (`net`, `fileops`, `proc`, `databases`, `cloud`, `k8s`, `containers`, `secrets`, `vcs`, `notify`, `crypto`, `data`). It writes no audit record, opens no approval, and records no denial. `--json` prints the report as JSON. `whoami` reads only the calling session. The local admin API serves any named session with `POST /v1/whoami` and `{"session_id": "...", "caps": true}`.

## Required role

`??` and `admin_explain` read a role string when the decision result contains one. The public `EvaluatePolicy` method still returns `(allowed, reason, error)`.

A valid role matches `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,64}$`. The engine uses a top-level `required_role` string when it is valid. Otherwise it uses `metadata.required_role` when `metadata` is an object. An invalid or missing role is empty, and the operator prompt uses `<role>`.

```rego
package adssh.authz

default allow = false

required_role := "ops"
```

A metadata-only role:

```rego
package adssh.authz

default allow = false

metadata := {"required_role": "netops"}
```

## Examples

`policy/examples/` and `ee/policy/bundles/` are starter policies. They compile. Loading them does not by itself evaluate a decision.

- `policy/examples/cert_principal.rego` treats certificate principals as `input.groups`.
- `policy/examples/lease_bounds.rego` bounds a lease to vault, a TTL of at most 300 seconds, destination `TOKEN`, and command `deploy`.
- `policy/examples/agent-destructive.rego` is the short destructive-agent rule.
- `policy/examples/agent-session.rego` allows one MCP agent id and one session id. Tool arguments named `agent_id` or `session_id` do not replace those fields.
- `policy/examples/explained.rego` returns `allow`, `deny_reason`, `required_role`, `rule`, and `required_entitlement`.
- `policy/examples/mirror_share.rego` caps `mirror share` at 30 minutes and lets only `oncall-lead` grant console access.
- `ee/policy/bundles/ai-agent.rego` allows a fixed set of MCP tools. `admin_*` and `identity_*` are absent from `mcp_tools`, so those tools fail closed under that bundle.
- `ee/policy/bundles/admin-api.rego` is the role-separated admin API starter.

## Structured input

Policies can read the objects the shell already fills:

- `input.command` and `input.args`
- `input.lease` for a lease request (`source_type`, `source_name`, `destination`, `ttl_seconds`, `command`, `delivery`)
- `input.agent` for an MCP call (`id`, `kind`, `risk`, `dry_run`, `session_id`)
- `input.gateway` for gateway authorization
- `input.elevation` for an active elevation claim
- `input.groups` for session principals, including certificate principals

## Session sharing

`mirror share --with <user> --for <duration> [--console]` lets one user view (or, with `--console`, also type into) the calling session until the grant expires. A grant lasts at most 24h. `mirror unshare [--with <user>]` revokes it. Without a grant, a user can attach only to their own sessions, or to any session while holding `adssh-admin` or `os-root` (directly or by an active elevation). A managed-agent session cannot share or attach. Grants are held in memory by the process that runs the shell and end with it.

The gate evaluates `mirror share` as command `mirror` with the argv in `input.args`, so a policy can bound the duration or the console flag. Every grant, revoke, expiry, attach, and refusal is an audit event (`MIRROR_SHARE`, `MIRROR_UNSHARE`, `MIRROR_SHARE_EXPIRED`, `MIRROR_ATTACH`, `MIRROR_DENIED`).

`sah/1` `execute` uses the same policy gate. A frame `lease_id` does not authorize the command.
