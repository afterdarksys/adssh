# MCP and agent governance

`adssh-mcp` is a local MCP server. It is not a second public API. Build it with `make build-mcp`.

## Process claim

The process creates one session id, `mcp-<unix nanos>`, registers it, and puts that id on `input.agent.session_id`. The agent id comes from `--agent-id` or `ADSSH_AGENT_ID`. When neither is set, the id is `mcp-<pid>`.

Tool arguments named `agent_id` or `session_id` are command arguments. They do not replace the process claim. `policy/examples/agent-session.rego` shows a policy that requires both bound fields.

## Tool allowlist

`ADSSH_AGENT_TOOLS_FILE` or `--agent-tools-file` loads one tool name per line. `#` comments are skipped. The flag overrides the environment. An empty flag value means the allowlist is not configured.

Unset means policy is the only tool gate. A configured file, including an empty file, is an allowlist. An empty allowlist denies every tool with `agent: tool is not entitled`. A missing file, a non-regular file, a file larger than 64 KiB, or a name outside `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,64}$` fails closed at startup with exit code 2, before the engine is constructed.

`policy/bundles/ai-agent.rego` lists `eval_starlark`, `run_shell`, `list_sessions`, `cloud_query`, and `audit_log`. `admin_*` and `identity_*` are absent, so that bundle denies them.

## Gate order

Each tool runs entitlement, then the destructive dry-run check, then policy, then the handler.

`--require-agent-dry-run` or `ADSSH_AGENT_REQUIRE_DRY_RUN=true` (only the exact fold of `true`, plus the flag) requires `dry_run=true` before a destructive `run_shell` call. The error is `agent: destructive action requires dry_run=true`. The dry-run path does not execute the command. Entitlement is checked first, so an unentitled destructive call returns the entitlement error.

Destructive classification for `run_shell` matches fragments such as `rm`, `delete`, `destroy`, `terminate`, `kubectl delete`, `terraform apply`, `terraform destroy`, `tofu apply`, `tofu destroy`, `docker rm`, `docker rmi`, `git push --force`, and `chmod 777`.

`admin_list_*`, `admin_explain`, and `identity_status` are read. `identity_device_login` is mutable.

## Governed tools

These tools are registered. They still pass the gate above. A missing security engine returns `agent: security engine is not bound`.

| Tool | What it returns |
| --- | --- |
| `admin_list_sessions` | Sessions in this process. |
| `admin_list_approvals` | Public request ids. The approval token is omitted. |
| `admin_list_recordings` | Regular JSONL recordings. |
| `admin_list_elevations` | Chain lines plus active grants. A missing chain fails closed. |
| `admin_list_leases` | Lease metadata. Command text and secret values are omitted. |
| `admin_explain` | A denial explanation. The command is split on whitespace and is not executed. |
| `identity_status` | `session_id`, `user`, and `principals`. No token and no elevation. |
| `identity_device_login` | Device-login client. Result is `token_file` and `fingerprint`. The bearer is not printed. |

`identity_device_login` stores an opaque bearer in a mode `0600` file and sets the session user with no groups. It is not an OIDC group import. The authorization server stays in systemapi. A bad duration returns `device_login_failed` and does not dial.

There is no approve or deny tool. An agent must not decide a four-eyes request. Registering these tools also forbids every four-eyes decision in the `adssh-mcp` process, so `4eyes approve` through `run_shell` or `eval_starlark` fails too. A human approves in the shell or with a named key on `admin serve`.

Neither `admin_list_approvals` nor `GET /v1/approvals` returns the stored token.

None of these tools provision a machine, enroll it, or hand adssh a systemapi lease.
