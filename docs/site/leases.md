# Leases

`lease` fetches one secret and injects it into one governed command. The secret is not stored in the HMAC chain and it is not stored in the evidence bundle.

```text
lease --from env:NAME|file:path|vault:path?field=KEY|aws-sm:name?region=REGION|azure-kv:vault/name|gcp-sm:project/name --via env|stdin|fd [--as DEST] [--ttl duration] -- command [args...]
```

## Delivery

`--via` defaults to `env`. The destination name defaults to `TOKEN`, so the child sees `TOKEN` and the audit line records `as=TOKEN` and `delivery=env`.

`--via stdin` writes the secret to the child stdin and sets the destination to `stdin`. `--as` is rejected.

`--via fd` passes the secret on inherited file descriptor 3. The destination is `fd:3`. `--as` is rejected. The writer copies the secret and then zeros its buffer.

NUL bytes are rejected for environment delivery. The TTL must be greater than zero and at most 24 hours. The binary default is 5 minutes.

A pipe failure revokes the lease with reason `delivery-error` before the command is granted.

## Policy

`input.lease` is visible to Rego before the secret is fetched. `policy/examples/lease_bounds.rego` allows only:

- `input.command == "lease"`
- `source_type == "vault"`
- `ttl_seconds` greater than 0 and at most 300
- `destination == "TOKEN"`
- `command[0] == "deploy"`

`source_type` is the prefix of `--from`: `env`, `file`, `vault`, `aws-sm`, `azure-kv`, or `gcp-sm`. `delivery` is `env`, `stdin`, or `fd`.

A policy denial of `lease` can send the optional approval webhook. The notice does not fetch the secret.

## Evidence

Lease request, grant, and revoke events are HMAC chain lines. `evidence` builds a lease view from those lines after it hashes the chain entries. The digest does not include that view. Command text is omitted from the lease list. `GET /v1/leases` and MCP `admin_list_leases` fail closed with `chain_unavailable` when the chain path is not configured.

A `sah/1` frame `lease_id` does not authorize `execute`. The provision, enroll, and execute handoff is not wired.
