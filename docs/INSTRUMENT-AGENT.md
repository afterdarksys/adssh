# adssh Instrumentation Agent

**Status:** Normative
**Package:** `internal/agent`

---

## Overview

The instrumentation agent is a small, hardened HTTP listener that lets the
AfterDark control-plane API ask a running `adssh` to execute **named,
pre-approved, read-only instrumentation tasks** — and nothing else. Every
request flows through adssh's existing policy + audit chokepoint
(`security.EvaluatePolicy`, `security.LogCommand`, and the HMAC audit hash-chain)
exactly as a human-typed command would.

It is deliberately **not** a general remote-exec endpoint or C2 channel. The
network can name only a *task*; the virtual binary and its arguments come from a
local, operator-controlled allowlist file and are **never** taken from the
request body.

---

## Enabling the agent

```bash
# Flag form (localhost bind recommended)
adssh --serve-agent 127.0.0.1:7777

# Environment form
export ADSSH_AGENT_SERVE=127.0.0.1:7777
export ADSSH_AGENT_TOKEN="$(openssl rand -hex 32)"   # REQUIRED — no token, no start
adssh
```

Configuration (`ADSSH_*` env vars, overridable by flags):

| Variable | Flag | Meaning | Default |
|---|---|---|---|
| `ADSSH_AGENT_SERVE` | `--serve-agent <addr>` | Listener address | *(off)* |
| `ADSSH_AGENT_TOKEN` | — | Bearer token the agent requires | *(none — must be set)* |
| `ADSSH_AGENT_TASKS` | — | Path to the task allowlist YAML | `~/.adssh/instrument-tasks.yaml` |

`adssh --init` scaffolds a starter (empty, deny-everything) `instrument-tasks.yaml`.

---

## Endpoints

All responses are JSON.

### `GET /v1/health`
No authentication. Reveals no task or configuration data.
```json
{"status":"ok"}
```

### `GET /v1/tasks`
Requires auth. Lists the allowlisted task names and descriptions.
```json
{"tasks":[{"name":"loadavg","description":"System load average","risk":"low"}]}
```

### `POST /v1/instrument`
Requires auth. Body names **only** a task:
```json
{"task":"loadavg","dry_run":true}
```
`dry_run` defaults to `true` when omitted. Response:
```json
{"task":"loadavg","ok":true,"exit":0,"output":"0.15 0.10 0.05 ...\n","truncated":false}
```

Flow: authenticate → look the task up in the allowlist → build a `PolicyContext`
with an `Agent` claim (`kind=instrument`, `risk`, `dry_run`) → `EvaluatePolicy`
→ dispatch the mapped virtual binary with its **fixed** args → return captured
output. Every path (allowed, denied, unknown, error) is written to the audit log
and hash-chain via `LogCommand`.

---

## Authentication

Bearer token in the `Authorization` header:

```
Authorization: Bearer <ADSSH_AGENT_TOKEN>
```

- The token is compared using `crypto/subtle.ConstantTimeCompare` over SHA-256
  digests of both sides, so the comparison is constant-time and independent of
  the presented token's length.
- A missing or empty configured token makes the agent **refuse to start**
  (fail closed).
- A missing or wrong request token is `401`.
- The token is **never** logged and **never** echoed in an error body.

---

## The tasks file

Default location `~/.adssh/instrument-tasks.yaml`, overridable with
`ADSSH_AGENT_TASKS`. Grammar:

```yaml
tasks:
  <task-name>:
    vbin: <virtual-binary-name>   # a registered adssh virtual binary
    args: [<fixed>, <args>]       # FIXED args passed to the vbin (never from the client)
    description: <text>           # surfaced by GET /v1/tasks
    risk: <label>                 # advisory; threaded into the policy AgentClaim
```

Example (Linux; `proc get` is read-only — never allowlist `proc set`):

```yaml
tasks:
  loadavg:
    vbin: proc
    args: ["get", "/proc/loadavg"]
    description: "System load average (1/5/15 min)"
    risk: low
  meminfo:
    vbin: proc
    args: ["get", "/proc/meminfo"]
    description: "Kernel memory statistics"
    risk: low
```

Rules:
- The network request names **only** the task. The `vbin` and `args` are read
  from this file and are never client-supplied.
- A missing file is treated as an **empty** allowlist (every task is `404`), so a
  host with no configuration refuses everything while still serving `/v1/health`
  and an empty `/v1/tasks`.
- A malformed file is a startup error (fail closed).
- Only allowlist genuinely **read-only** tasks. The shipped default is empty on
  purpose.

---

## Security model

`Threats:` (see the block at the top of `internal/agent/agent.go`).

**Defends against**
- **Unauthenticated task execution** — constant-time bearer-token auth; no token
  configured ⇒ the agent refuses to start.
- **Arbitrary command / argument injection from the network** — the body names
  only a task; the vbin + args come from the local allowlist.
- **Replay / resource exhaustion via oversized bodies** — bodies are capped with
  `http.MaxBytesReader` (64 KiB); over-cap ⇒ `413`, never buffered whole.
- **Task escalation beyond the allowlist** — unknown task ⇒ `404`; every task is
  still gated by the Rego policy (`deny ⇒ 403`) and audited on every path.
- **Token disclosure** — the token is never logged or echoed.

**Does NOT defend / out of scope**
- This is **not** a general RPC, remote shell, or C2. It runs only named,
  allowlisted, read-only tasks.
- **Transport confidentiality.** The agent speaks plain HTTP — bind to
  `127.0.0.1` or place it behind a TLS / mTLS terminator.
- The operator is responsible for allowlisting only read-only virtual binaries
  and for the Rego policy governing the `instrument` agent kind.

### Failure modes (all fail closed)

| Condition | Result |
|---|---|
| No token configured | agent does not start |
| Missing/wrong request token | `401` |
| Body over 64 KiB | `413` |
| Unknown task | `404` |
| Policy denies (or policy error) | `403`, audited |
| Task maps to an unknown virtual binary | `500`, refuses to run |

---

## Example Rego (restrict the agent by kind)

```rego
package adssh.authz

# Only allow the instrumentation agent to run low-risk, dry-run tasks.
default allow = false
default deny_reason = "not permitted"

allow if {
    input.agent.kind == "instrument"
    input.agent.risk == "low"
    input.agent.dry_run == true
}
```
