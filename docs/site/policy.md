# Policy authoring

Policies are Rego. The engine queries `data.adssh.authz`. A loaded policy that errors, omits `allow`, or returns a non-bool `allow` denies. No policy loaded allows, unless `RequirePolicy` refused to construct the engine.

Start from deny:

```rego
package adssh.authz

default allow = false
```

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

`policy/examples/` and `policy/bundles/` are starter policies. They compile. Loading them does not by itself evaluate a decision.

- `policy/examples/cert_principal.rego` treats certificate principals as `input.groups`.
- `policy/examples/lease_bounds.rego` bounds a lease to vault, a TTL of at most 300 seconds, destination `TOKEN`, and command `deploy`.
- `policy/examples/agent-destructive.rego` is the short destructive-agent rule.
- `policy/examples/agent-session.rego` allows one MCP agent id and one session id. Tool arguments named `agent_id` or `session_id` do not replace those fields.
- `policy/bundles/ai-agent.rego` allows a fixed set of MCP tools. `admin_*` and `identity_*` are absent from `mcp_tools`, so those tools fail closed under that bundle.
- `policy/bundles/admin-api.rego` is the role-separated admin API starter.

## Structured input

Policies can read the objects the shell already fills:

- `input.command` and `input.args`
- `input.lease` for a lease request (`source_type`, `source_name`, `destination`, `ttl_seconds`, `command`, `delivery`)
- `input.agent` for an MCP call (`id`, `kind`, `risk`, `dry_run`, `session_id`)
- `input.gateway` for gateway authorization
- `input.elevation` for an active elevation claim
- `input.groups` for session principals, including certificate principals

`sah/1` `execute` uses the same policy gate. A frame `lease_id` does not authorize the command.
