# adssh MCP Reference

This document is the complete operational reference for adssh. It covers MCP setup,
the policy system, tool selection guidance, all 6 tool references, DevOps workflow
scenarios, audit trail usage, and common pitfalls.

---

## MCP Setup

### Fresh Developer Walkthrough

**Step 1 — Build the binary**

```bash
go build -o adssh-mcp ./cmd/adssh-mcp
```

This produces the `adssh-mcp` binary in the project root. Note the absolute path for use
in `.mcp.json` below.

**Step 2 — Create a policy file**

```bash
mkdir -p ~/.adssh
cat > ~/.adssh/policy.rego << 'EOF'
package adssh.authz
default allow = true
default deny_reason = ""
EOF
```

This is the dev quickstart allow-all policy. Every MCP tool call is policy-gated —
you must have a policy file in place. See the [Policy System](#policy-system) section for
production rules.

**Step 3 — Configure `.mcp.json`**

Create `.mcp.json` in your project root. The **env-var approach is primary** — secrets
stay out of the args array:

```json
{
  "mcpServers": {
    "adssh": {
      "command": "/absolute/path/to/adssh-mcp",
      "env": {
        "ADSSH_MCP_API_KEY": "${ADSSH_MCP_API_KEY}",
        "ADSSH_POLICY": "${HOME}/.adssh/policy.rego"
      }
    }
  }
}
```

Replace `/absolute/path/to/adssh-mcp` with the full path to the binary you built in Step 1.

**Alternative: CLI flags form** (env vars preferred — shown here for reference):

```json
{
  "mcpServers": {
    "adssh": {
      "command": "/absolute/path/to/adssh-mcp",
      "args": ["--policy", "${HOME}/.adssh/policy.rego"]
    }
  }
}
```

**Step 4 — Set environment variables**

```bash
export ADSSH_MCP_API_KEY=your-key-here
```

**Step 5 — Verify**

Restart Claude Code and confirm `adssh` appears in the MCP server list. If the server
starts successfully, the audit log will contain `"Policy loaded from ~/.adssh/policy.rego"`.

---

### Environment Variables Reference

All ADSSH_* variables are read by `config.LoadFromEnv()`. CLI flags (`--policy`, `--api-key`)
override the corresponding env vars when passed to the binary.

| Env Var | Default | Purpose |
|---------|---------|---------|
| `ADSSH_MCP_API_KEY` | (none) | API key for MCP server authentication |
| `ADSSH_POLICY` | `~/.adssh/policy.rego` | Path to Rego policy file |
| `ADSSH_AUDIT_LOG` | `~/.adssh/audit.log` | Path to audit log file |
| `ADSSH_RESTRICTED` | `0` | Enable sandboxed mode (`1`, `true`, or `yes`) |
| `ADSSH_SERVE` | (none) | Start SSH server on this address (e.g. `:2222`) |
| `ADSSH_HOST_KEY` | `~/.adssh/host_key` | SSH host key path |
| `ADSSH_AUTHORIZED_KEYS` | `~/.adssh/authorized_keys` | SSH authorized keys path |
| `ADSSH_PROFILE` | `~/.adsshprofile` | Login profile script path |
| `ADSSH_RC` | `~/.adsshrc` | Interactive RC script path |
| `ADSSH_AUDIT_URL` | (none) | Webhook URL for remote SIEM logging |
| `ADSSH_AUDIT_TOKEN` | (none) | Bearer token for audit webhook |
| `ADSSH_ENTITLEMENTS` | (none) | Path to legacy YAML entitlements (deprecated) |

---

## Policy System

Every MCP tool call passes through the `policyGate` wrapper **before** the tool executes.
The gate evaluates the Rego policy and either allows execution or returns
`"access denied: <reason>"` to the caller.

### PolicyContext Fields

When `policyGate` fires, it calls `BuildPolicyContext(toolName, []string{}, "")`. The Rego
`input` document has these exact fields:

| Field | Type | Value for MCP Calls |
|-------|------|---------------------|
| `input.user` | string | OS username running the MCP server |
| `input.groups` | []string | OS groups of the running user |
| `input.command` | string | Tool name, e.g. `"eval_starlark"`, `"run_shell"` |
| `input.args` | []string | Always `[]` for MCP tool calls |
| `input.time` | string | RFC3339 UTC timestamp of the call |
| `input.session_id` | string | Always `""` for MCP calls (no SSH session) |

### Required Rego Structure

Every policy file must declare the `adssh.authz` package and set both defaults:

```rego
package adssh.authz

default allow = true      # or false to deny-by-default
default deny_reason = ""  # shown in "access denied: <reason>"
```

OPA evaluates `data.adssh.authz` and reads `allow` (bool) and `deny_reason` (string).

### Dev Quickstart — Allow All

```rego
package adssh.authz
default allow = true
default deny_reason = ""
```

Save to `~/.adssh/policy.rego` to get started immediately.

### Example: Deny a Specific MCP Tool

Adapted from `policy/examples/restrict_sudo.rego` — deny `container_exec` for all users:

```rego
package adssh.authz

default allow = true
default deny_reason = ""

allow = false {
    input.command == "container_exec"
}

deny_reason = "container_exec is disabled by policy" {
    input.command == "container_exec"
}
```

### Example: Group-Based Deny (From `policy/examples/ops_group_only.rego`)

Only members of the `ops` group may execute any tool:

```rego
package adssh.authz

default allow = false
default deny_reason = "only members of the ops group may run commands"

allow {
    some group in input.groups
    group == "ops"
}

deny_reason = "" {
    some group in input.groups
    group == "ops"
}
```

### More Examples

See `policy/examples/` in the project for additional patterns:
- `ops_group_only.rego` — group-based allow
- `restrict_sudo.rego` — command-specific deny
- `migrate-from-yaml.rego` — per-user/per-group allowlist migrated from YAML entitlements

### Policy Awareness

If a tool call returns `"access denied"`, a Rego rule blocked it. To investigate:

1. Use `audit_log` with `filter="denied"` to see blocked calls
2. Review `~/.adssh/policy.rego` (or the path in `ADSSH_POLICY`)
3. Adjust the rule and restart the MCP server to reload policy

Policy file location: `~/.adssh/policy.rego` (override with `ADSSH_POLICY` env var or
`--policy` CLI flag).

---

## Tool Selection

Use this table to pick the right tool for each task:

| Situation | Use |
|-----------|-----|
| Need cloud namespace access (`aws.*`, `gcp.*`, `oci.*`) with arguments | `eval_starlark` |
| Single zero-argument cloud function call | `cloud_query` (simpler) |
| Multi-step Starlark logic, loops, conditionals, combining results | `eval_starlark` |
| POSIX pipeline: grep, awk, sed, file operations, system commands | `run_shell` |
| Anything easier as a shell one-liner | `run_shell` |
| Check what SSH sessions are active | `list_sessions` |
| Run something in a container without leaving artifacts | `container_exec` |
| Review recent activity or debug a policy denial | `audit_log` |

**Key insight:** `cloud_query` is a convenience shortcut for `eval_starlark` when calling
a zero-argument function. For anything with arguments or multi-step logic, use `eval_starlark`.

---

## Tool Reference

### eval_starlark

Execute a Starlark expression or multi-statement script in the adssh environment. Returns
print output and the final return value. The Starlark globals are initialized once at server
startup and shared across all calls — treat cloud namespace dicts as read-only.

**Parameters**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `code` | string | yes | — | Starlark code to evaluate |

**Return format** (plain text):

```
output: <print() output, empty if none>
result: <expression return value>
```

**Available Starlark globals:** `aws`, `gcp`, `oci`, `cloud`, `git`, `github`, `containers`,
`crypto`, `net`, `re`, `sys`, `data`, `sec`, `i18n`

**Example — describe running AWS instances:**

```
eval_starlark(code='result = aws["describe_instances"]("running")\nprint(result)')
```

Response:
```
output: [{"id":"i-0abc123","type":"t3.medium","state":"running"}, ...]
result: None
```

---

### run_shell

Execute a POSIX shell command. Uses `mvdan.cc/sh` — a pure Go POSIX shell interpreter,
NOT bash. Avoid bash-specific syntax (`[[`, `(( ))`, bash arrays, `$BASHPID`).
The `BashInterceptor` enforces policy on subcommands within the pipeline.

**Parameters**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `command` | string | yes | — | POSIX shell command to execute |

**Return format** (plain text):

```
exit_code: <int>
stdout: <string>
stderr: <string>
```

**Example — check disk usage:**

```
run_shell(command="df -h | grep -v tmpfs")
```

Response:
```
exit_code: 0
stdout: Filesystem      Size  Used Avail Use% Mounted on
        /dev/sda1        50G   12G   35G  26% /
stderr:
```

---

### list_sessions

List active SSH sessions. Returns a JSON array of session ID strings from the global session
registry.

**Parameters**

None.

**Return format** (JSON):

```json
["session-abc123", "session-def456"]
```

Returns `[]` when no sessions are active.

**Example — check active sessions:**

```
list_sessions()
```

Response:
```json
["session-a1b2c3d4", "session-e5f6g7h8"]
```

---

### cloud_query

Execute a single zero-argument function from a cloud namespace. Supports `aws`, `gcp`, `oci`,
and `cloud` namespaces. CRITICAL: calls the function with NO arguments. If the function
requires arguments, use `eval_starlark` instead.

**Parameters**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `namespace` | string | yes | — | Cloud provider: `aws`, `gcp`, `oci`, or `cloud` |
| `function` | string | yes | — | Function name within the namespace to call |

**Return format:** String representation of the Starlark return value.

**Example — list S3 buckets:**

```
cloud_query(namespace="aws", function="list_buckets")
```

Response:
```
["my-app-data", "my-backups", "my-logs"]
```

---

### container_exec

Run a command in an ephemeral Docker container. The container is created, the command
executes, logs are captured, and the container is removed. Also writes a JSONL audit record
to `~/.adssh/container_audit.jsonl`.

Requires Docker daemon running locally. Pulls the image on each call if not locally cached.

**Parameters**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `image` | string | yes | — | Docker image to use (e.g. `ubuntu:22.04`) |
| `cmd` | string | yes | — | Command as JSON array (e.g. `["cat","/etc/os-release"]`) or single string |

**Return format** (JSON):

```json
{
  "session_id": "a1b2c3d4e5f6g7h8",
  "exit_code": 0,
  "stdout": "...",
  "stderr": "...",
  "duration_ms": 1234
}
```

**Example — check OS release in a container:**

```
container_exec(image="ubuntu:22.04", cmd='["cat","/etc/os-release"]')
```

Response:
```json
{
  "session_id": "3f2a1b4c",
  "exit_code": 0,
  "stdout": "NAME=\"Ubuntu\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\n...",
  "stderr": "",
  "duration_ms": 3421
}
```

---

### audit_log

Query recent entries from the audit log (`~/.adssh/audit.log`). Returns the last N lines,
optionally filtered by substring. Every MCP tool call — including this one — is logged.

**Parameters**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `limit` | number | no | 50 | Maximum number of log entries to return |
| `filter` | string | no | (none) | Substring filter applied to each log line |

**Return format:** Newline-separated log lines. Returns `(no audit log entries)` if the
log file does not exist yet.

**Example — see all policy denials:**

```
audit_log(filter="denied")
```

Response:
```
2026-05-07T05:10:22Z POLICY_DENY user=alice command=container_exec: access denied by policy
2026-05-07T05:11:45Z POLICY_DENY user=alice command=run_shell: access denied: sudo is not allowed by policy
```

**Example — review your own recent eval_starlark calls:**

```
audit_log(limit=10, filter="eval_starlark")
```

---

## Workflows

### Workflow 1: Investigate SSH Sessions and Cloud State

Use when a team member reports something wrong and you want situational awareness.

1. **Check active sessions** — see who is connected:

   ```
   list_sessions()
   ```

   Returns: `["session-a1b2c3d4"]` — one active session.

2. **Query running cloud instances** — see what's running in AWS:

   ```
   eval_starlark(code='result = aws["describe_instances"]("running")\nprint(result)')
   ```

   Returns: list of running instances with IDs and types.

3. **Review recent activity** — confirm what commands were run:

   ```
   audit_log(limit=20)
   ```

   Returns: last 20 audit log entries showing tool calls and timestamps.

---

### Workflow 2: Shell Diagnostics with Container Investigation

Use when you need to diagnose a system issue and want to reproduce it in an isolated environment.

1. **Check disk usage on the host:**

   ```
   run_shell(command="df -h")
   ```

   Returns: disk usage by filesystem.

2. **Spin up an ephemeral container to investigate:**

   ```
   container_exec(image="ubuntu:22.04", cmd='["ps", "aux"]')
   ```

   Returns: process list from inside a fresh container.

3. **Confirm the container exec was logged:**

   ```
   audit_log(filter="container_exec")
   ```

   Returns: the audit entries for container_exec calls, including the session_id.

---

### Workflow 3: Debug a Policy Denial

Use when a tool call returns "access denied" and you need to understand what rule fired.

1. **Attempt the blocked tool call** — it returns an access denied error:

   ```
   run_shell(command="sudo systemctl restart nginx")
   ```

   Response: `access denied: sudo is not allowed by policy`

2. **Check the audit log for denials:**

   ```
   audit_log(filter="denied")
   ```

   Returns: entries showing which user, which command, and which policy rule triggered.

3. **Review and update the policy file** — edit `~/.adssh/policy.rego` (or the path in
   `ADSSH_POLICY`). Restart the MCP server to reload the policy.

---

## Audit Trail

Every MCP tool call is logged by `security.LogCommand()`:

- **Main audit log:** `~/.adssh/audit.log` (override with `ADSSH_AUDIT_LOG`)
- **Container audit:** `~/.adssh/container_audit.jsonl` — written by `container_exec` for
  each container run (separate JSONL file, includes image, cmd, exit_code, stdout, stderr)

**Useful audit_log filter patterns:**

| Filter | What it finds |
|--------|---------------|
| `filter="denied"` | All policy denial events |
| `filter="eval_starlark"` | All eval_starlark calls |
| `filter="run_shell"` | All run_shell calls |
| `filter="container_exec"` | All container_exec calls |

Use `audit_log` to review your own session history, verify a tool ran successfully,
or investigate unexpected behavior. The audit log persists across server restarts.

---

## Common Pitfalls

### `cloud_query` Cannot Pass Arguments

`cloud_query` calls the Starlark function with no arguments (`starlark.Call(thread, callFn, nil, nil)`).
If the function requires arguments (e.g. `describe_instances("running")`), you will get an error.

**Fix:** Use `eval_starlark` with the arguments embedded in the code:

```
eval_starlark(code='result = aws["describe_instances"]("running")')
```

Warning sign: `error calling aws.X: ...` returned by `cloud_query`.

---

### Starlark Globals Are Shared State

The `globals starlark.StringDict` is initialized once at server startup and passed to all
`eval_starlark` calls. If one call modifies a global (e.g. reassigns a namespace key), later
calls see the change.

**Fix:** Treat globals as read-only infrastructure. Use local variables within each code block:

```python
# Good — local variable
instances = aws["list_instances"]()

# Bad — reassigning a global
aws = None  # breaks all subsequent cloud calls
```

Warning sign: Unexpected values across separate tool calls.

---

### Missing Policy File = Allow-All Fallback

If `~/.adssh/policy.rego` does not exist when the server starts, `LoadPolicy` gets
`os.IsNotExist` and returns `nil` — the policy is not loaded. `EvaluatePolicy` returns
`(true, "", nil)` for every call — everything is allowed.

**Fix:** Always create the policy file before starting the server in production. Confirm the
audit log contains `"Policy loaded from ..."` after startup.

Warning sign: No `"Policy loaded from"` line in the audit log.

---

### `container_exec` Requires Docker Daemon

The tool creates a Docker client from environment and pulls the image before creating the
container. If Docker is not running, the call fails immediately.

**Fix:** Ensure Docker Desktop or Docker Engine is running. Verify with:

```bash
docker info
```

Warning signs: `"docker client error: ..."` or `"image pull failed: ..."` in tool response.

---

### `run_shell` Uses POSIX Shell (Not Bash)

`run_shell` uses `mvdan.cc/sh/v3` — a pure Go POSIX shell interpreter. Bash-specific syntax
will fail or behave differently.

**Avoid:** `[[`, `(( ))`, bash arrays, `$BASHPID`, process substitution `<(cmd)`,
`declare -a`, `local -n`.

**Fix:** Stick to POSIX-compatible syntax. For bash-specific operations, use `eval_starlark`
with `sys.exec_cmd()`.

Warning signs: Parse errors mentioning `[[`, `(( ))`, or unexpected syntax errors.
