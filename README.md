# adssh

A security-first, programmable DevOps shell. Write cloud automation, run shell commands, enforce OPA policies, and let AI agents drive it all — from one shell.

```
adssh> aws.ec2.list_instances(region="us-east-1")      # Starlark: cloud SDK
adssh> ls -la | jq '.name'                             # Shell: pipe to virtual jq
adssh> def deploy(env): containers.exec("deploy.sh", env=env)  # Define reusable functions
adssh> vbins                                            # List all built-in tools
```

## Install

```bash
git clone https://github.com/afterdarksys/adssh
cd adssh
make install        # installs adssh + adssh-mcp to $GOPATH/bin
adssh --init        # create ~/.adssh/ starter config
adssh --doctor      # check policy, audit, history, SSH, and host-tool readiness
adssh               # launch
```

Requires Go 1.26+.

## Commercial Demo

Run the local governed-access walkthrough:

```bash
make demo
```

The demo builds `adssh`, starts a disposable local TCP target, blocks an initial
gateway attempt, explains it with `??`, grants time-boxed `elevate` access,
proves gateway traffic, leases a redacted secret to one command, records the
session, and exports an evidence bundle. It prints the temporary workspace,
transcript, audit log, recordings, and evidence paths at the end.

`.adssh` files run as line-oriented shell scripts through the same policy,
audit, elevation, lease, gateway, and recording path as the interactive shell.
Prefix a line with `-` when the failure is expected and the script should keep
running, which is useful for demos that intentionally show denied access before
elevation.

## Release Packaging

Build release artifacts locally:

```bash
make package VERSION=v0.9.0
```

The packaging script emits cross-platform tarballs, `SHA256SUMS`, optional GPG
checksum signatures when `GPG_SIGN=1`, and optional `.deb`/`.rpm` packages when
the host has `dpkg-deb` or `rpmbuild`. Release tarballs include the binaries,
manpage, shell completions, policy bundles, docs, and the Homebrew formula
template under `packaging/homebrew/`. Each run also writes `provenance.json`
and `slsa-provenance.intoto.json` with artifact digests and build metadata.

## 5-minute tour

```bash
# 1. Launch
adssh

# 2. Shell commands work as normal
ls -la
git status
cat k8s.yaml | yq '.spec.replicas'    # virtual yq — no install needed

# 3. Starlark mode — cloud SDK built-in
instances = aws.ec2.list_instances(region="us-east-1")
print(instances)

# 4. Define a function, use it later in the same session
def restart_service(name):
    sys.exec_cmd("systemctl restart " + name)

restart_service("nginx")

# 5. Audited container exec
containers.exec("alpine", cmd=["sh", "-c", "cat /etc/os-release"])
containers.audit()     # see what ran
containers.replay(session_id)   # re-run exact params

# 6. Session supervision (metadata, mirroring, console, audited kill)
mirror list
mirror view <session_id>
mirror console <session_id>
mirror kill <session_id>

# 7. GitHub operations
prs = github.list_prs("afterdarksys/adssh")
github.create_pr("afterdarksys/adssh", title="fix: ...", head="feature-branch", base="main", body="...")

# 8. List all virtual binaries
vbins
jq --help
```

## Dual-mode REPL

The shell auto-detects whether you're typing Starlark or shell:

| Input | Mode |
|---|---|
| `ls -la` | Shell |
| `aws.ec2.list_instances()` | Starlark |
| `def foo():` | Starlark (multi-line — press Enter on blank line to finish) |
| `x = 5` | Starlark |
| `!ls -la` | Force shell |
| `$ ls -la` | Force shell |

Multi-line Starlark works naturally:
```
adssh> def greet(name):
...       return "hello " + name
...   
adssh> greet("world")
"hello world"
```

A bracketed paste that contains a newline is held. The editor inserts `[paste held: N lines]` and does not run it. `safepaste show` prints the paste, `safepaste run` executes it chunk by chunk, each chunk in its own mode (shell, Starlark or a flow block) through the same policy gate as a typed command, and `safepaste drop` discards it. A paste is rejected, not held, when it carries bytes after its own end marker, when it stays open with no new bytes for two seconds, when it contains a control byte other than tab or newline, or when it is over 1 MiB. A held or rejected paste at a continuation prompt is dropped from the block being typed. A terminal that does not bracket pastes looks the same as typing.

Shell `if`/`then`/`else`/`fi` runs as a shell program. A one-line form is `if true; then echo yes; else echo no; fi`. Brace blocks run on exit status: `if true { echo yes } else { echo no }` and `try { false } catch { echo recovered }`. Catch runs only after a non-zero exit status. A policy denial stays a denial. Starlark `if expr:` stays Starlark.

`\g` in `PROMPT` or `RPROMPT` shows the current git branch, or a 7-character hash for a detached HEAD. It stays empty until `ADSSH_GIT_PROMPT=1` or `set gitprompt on`. `set gitprompt off` turns it off again. The segment reads `.git/HEAD` and never runs git, so a cloned repository's `core.fsmonitor` or filter commands cannot run on a prompt draw. It has no dirty marker, because that needs `git status`. Restricted mode and SSH sessions refuse `set gitprompt on` and ignore `ADSSH_GIT_PROMPT`. A directory that is not a repository, or a HEAD it cannot read, leaves the segment empty.

Pre-enter highlighting colours the line you are typing: red when policy would deny a command in it, yellow when it looks destructive (`rm -rf`, `kubectl delete`, `terraform destroy`, `git push --force`, the same check the MCP `run_shell` dry-run gate uses). It is off until `ADSSH_HIGHLIGHT=1` or `set highlight on`, and `set highlight on` itself passes the policy gate. It needs a terminal and is never on in the menu REPL. The line is only parsed: nothing is expanded or run, and the policy is asked through the same explanation `why` uses, 150 ms after you stop typing, without blocking input or writing audit entries. In an SSH session only the destructive check applies. The colour is advice; the gate still decides when you press Enter.

`confirm <command>` previews a command before it runs: the command, its risk class, the policy decision with any denied or approval stage, and the matched rule or required role. It then asks `run it? [y/N]` on the terminal and runs the command through the normal gate only on `y`. `confirm --dry-run <command>` prints the preview and stops. `confirm` refuses when stdin is not a terminal, and never runs a command the policy would deny. `confirm` is gated like any command, so a policy can require it (`input.command == "confirm"`).

Ctrl-C during a Starlark line (a long loop, a function call) cancels it at its next step, prints `interrupted`, and returns to the prompt; the next line runs normally. `sys.parallel` watches the same cancel and stops its running commands within a few hundred milliseconds. Ctrl-C during a shell command interrupts that command as before.

Background commands (`cmd &`) run inside the shell interpreter and `wait` waits for them. adssh does not list background jobs: there is no `jobs`, `fg` or `bg`. A hangup of the shell sends SIGHUP to its process group, so background commands end with it.

## Starlark namespaces

| Namespace | What it does |
|---|---|
| `aws` | EC2, S3, ECS, Lambda, CloudWatch (get_metric, list_metrics, alarms), Route 53 (list_zones, list_records, upsert_record) |
| `gcp` | Compute, Storage, GKE (list_clusters, describe), Pub/Sub (list_topics, publish, pull), Cloud Run (list_services) |
| `oci` | Compute, Storage |
| `git` | clone, status, add, commit, push, pull, log |
| `github` | repos, PRs, issues, releases, workflows |
| `containers` | exec (audited), list, audit, replay, clean |
| `data` | json_parse/dump, yaml_parse/dump, assert_type, validate (JSON Schema) |
| `sys` | exec_cmd, exec_async, parallel, read_file, write_file, getenv, load_plugin, load_plugins |
| `net` | tcp_send, http_get, dial, dial_tls, dial_udp |
| `str` | split, join, fields, trim, replace, sprintf, slugify, template, ... |
| `log` | info, warn, error (audit stream) |
| `crypto` | md5, sha256 |
| `re` | match (RE2), pcre_match |
| `sec` | audit, is_restricted, file_hash, check_policy |
| `i18n` | load, set_lang, T |
| `notify` | slack, webhook, pagerduty, teams |

`sys.parallel` runs a list of command strings with a bounded number of goroutines. Each string goes through the same gate as `sys.exec_cmd`. The call returns stdout in input order. A denial, a non-zero exit, a timeout, or an output overrun fails the call. A list that is empty, too long, or not all strings runs nothing. Restricted mode does not provide `parallel`. `par` remains the shell tool that stamps one argv template across items.

`data.assert_type(value, expected)` returns `value` or fails naming the type it got and the types it wanted (`"dict"` or `["int", "float"]`). `data.validate(schema, value, strict=False)` checks `value` against a JSON Schema (draft 2020-12 unless `$schema` says otherwise). `schema` is a dict or a JSON or YAML string. It returns `True` or a list of `{path, message}`; `strict=True` fails instead. A `$ref` outside the schema fails: no network or file loads. Schema and value are capped at 1 MiB and the check at 2 seconds.

`str.slugify(s, sep="-", max=80)` lowercases, strips accents (NFKD), and joins runs of letters and digits with `sep`. `str.template(tmpl, vars={}, strict=True)` renders a Go `text/template`. Only the comparison, logic and `printf` functions exist; `call`, `html`, `js` and `urlquery` fail. A template cannot read files, call out, or include anything not defined in its own text. `strict=True` fails on a missing key. Template and output are capped at 1 MiB and rendering at 2 seconds.

`log.info(msg, **fields)`, `log.warn` and `log.error` write `STARLARK_LOG level=... session=... msg=... k=v` to the audit log and hash chain, then print the same line to stderr. Fields are redacted. If the audit write fails the call fails and prints nothing. A policy gates them as `starlark.log.*` in the `audit` capability group.

`net.dial_udp(host, port, data, timeout=5)` sends one datagram and returns the first reply, capped at 64 KiB. No reply within the timeout is an error. It is gated like `net.dial`.

`aws.route53.upsert_record(zone_id=, name=, type=, values=[...], ttl=300)` and `aws.route53.delete_record(zone_id=, name=, type="A")` take keyword arguments only, so the gate sees the record as `"name"="<record>"`. Record names must be canonical (lowercase, ending in a dot, no `\NNN` escapes); Route 53 treats other spellings as the same name, so they are refused rather than let past a rule on the canonical one. Upsert and delete carry the `dns` capability on top of `cloud`, so a policy can deny DNS changes and keep reads. `gcp.pubsub.pull(project, subscription, max=10, ack=True)` acknowledges what it returns; with `ack=False` the messages are redelivered. `ack` is a required keyword so a policy can always match on it. `notify.teams(webhook_url="", title=, text="", color="")` posts an Adaptive Card to a Teams Workflows or legacy incoming webhook. The URL must be https to a public DNS name, and an empty `webhook_url` reads `TEAMS_WEBHOOK_URL`, which keeps the secret URL out of the audit log. Restricted mode omits `gcp.gke`, `gcp.pubsub`, `gcp.run`, `aws.cloudwatch`, `aws.route53` and `notify.teams`.

Restricted mode keeps `data.assert_type`, `data.validate`, `str.slugify` and `str.template`, and omits `log.*` and `net.*`.

Starlark plugins live in `~/.adssh/plugins/<name>/` as `manifest.yaml` and `plugin.star`. Nothing in that directory loads at startup. `plugin load <name>` and `plugin load --all` read them only when asked. `plugin load --all` checks every plugin first and loads none if any check fails. `sys.load_plugins` does the same load into the current session. Restricted mode does not provide `sys.load_plugins` and refuses `plugin load`. `sys.load_plugin` still loads a Go `.so`.

## Virtual binaries

Built-in tools that work without installing anything. Type `vbins` to list them all, `<name> --help` for usage.

| Binary | Description |
|---|---|
| `jq` | JSON processor |
| `yq` | YAML processor |
| `http` | HTTP GET client |
| `mirror` | Live session metadata, viewer and console for your own sessions, audited termination; supervising other users' sessions and time-boxed `share`/`unshare` grants are enterprise build |
| `admin` | Local admin API for sessions, gateways, approvals, evidence, and explanations (enterprise build) |
| `identity` | OIDC identity import, device login, and short-lived SSH certificate issuance (enterprise build) |
| `cmdgen` | Cloud CLI command generator |
| `package` | Cross-platform package manager |
| `proc` | `/proc` filesystem reader/writer (Linux) |
| `grant` | Temporary role escalation (enterprise build) |
| `elevate` | Time-boxed break-glass elevation with reason and audit trail (enterprise build) |
| `gateway` | Policy-audited local TCP gateway for SSH and internal services (enterprise build) |
| `pick` | Charm-powered fuzzy selector for arguments, stdin, or JSON choices |
| `nav` | Interactive three-column file navigator with previews |
| `from` / `where` / `select` / `to` | JSONL pipeline for JSON, YAML, CSV, and struct-shaped JSON |
| `why` | Side-effect-free policy/RBAC/CM/four-eyes explanation |
| `whoami` | Session user (like the OS `whoami`); `-v` adds principals, identity source, elevation, and agent; `--caps` previews entitlements and what policy allows, without side effects |
| `??` | Explain the last blocked command in the current session |
| `runbook` | Typed Starlark runbooks with governed argv-only steps |
| `plugin` | Load checked Starlark plugins from the config plugins directory |
| `par` | Bounded parallel execution with per-child authorization |
| `evidence` | Verified, filtered HMAC-chain evidence bundles (enterprise build) |
| `lease` | TTL-bounded command-scoped secrets from environment, private files, Vault, and cloud secret managers (enterprise build) |
| `darkscan` | Simulated malware-scanner demo (no security verdict) |
| `memforensics` | Simulated memory-forensics demo (no process inspection) |
| `4eyes` | Dual approval for commands that match a rule (enterprise build) |
| `cm` | Change-management tickets for covered commands (enterprise build) |
| `grid` / `flight` / `agent` / `worktree` / `repo` | sah-grid fleet commands (enterprise build) |

"Enterprise build" means `go build -tags ee` (BSL 1.1, `ee/`). The core build (`go build`, Apache 2.0) keeps these names, and running one prints that it is part of the enterprise build; it never falls through to a program of the same name on `PATH`. In the core build a command that matches a four-eyes rule, or that strict change management (`ADSSH_CM_STRICT=1` with `ADSSH_CM_PATTERNS`) covers, is refused, because the core build cannot approve it. SSH `direct-tcpip` forwarding is refused, and `adssh sah` exits with an error.

### Advanced VBIN workflows

```bash
# Fuzzy terminal selection and navigation
printf 'dev\nstaging\nproduction\n' | pick --query prod
nav ~/src

# Structured pipelines remain ordinary POSIX byte streams (JSONL internally)
cat services.json | from json | where 'row["cpu"] > 50' | select name,cpu | to table
cat services.yaml | from yaml | to struct name:string,cpu:int

# Explain governance without executing or opening an approval request
why -- kubectl delete namespace production
??   # after a denied command, explain what blocked it

# Import signed OIDC claims into this session, then inspect admin state
# issuer, JWKS URL and audience come from ADSSH_OIDC_{ISSUER,JWKS_URL,LOGIN_AUDIENCE}, never from flags
identity oidc import --env ADSSH_OIDC_TOKEN
identity status
admin sessions --json
admin gateways
admin approvals
admin explain -- gateway start --target bastion.internal:22
# read-only key; approve/deny need a named key from ADSSH_ADMIN_KEYS (name=key file, 0600)
ADSSH_ADMIN_API_KEY="$(openssl rand -hex 16)" admin serve --listen 127.0.0.1:8787

# Create a local SSH CA and issue a short-lived user certificate
identity ssh-ca init --out ~/.adssh/ca_user_key
identity ssh-ca issue --ca ~/.adssh/ca_user_key --pub ~/.ssh/id_ed25519.pub --principal alice --principal ops --for 15m --out ~/.ssh/id_ed25519-cert.pub

# Break-glass for one session with a visible expiry and audit entry
elevate request prod-admin --for 10m --reason "incident INC-1042"
elevate status
elevate drop

# Open a governed local gateway to an internal SSH target
gateway start --listen 127.0.0.1:0 --target bastion.internal:22 --name prod-bastion
gateway list
gateway stop gw-1

# Native SSH jump traffic through adssh --serve is also policy-gated
ssh -J operator@adssh-gateway:2222 user@bastion.internal

# Typed Starlark procedures: every step is an argv list and is re-authorized
ADSSH_RUNBOOK_DIR=examples/runbooks runbook run diagnose --param path=. --dry-run

# Parallel child commands are individually policy/RBAC/CM/four-eyes checked
par --jobs 4 api worker scheduler -- printf '%s\n' '{}'

# Export verified audit evidence, or lease a secret to one command only
evidence --session "$SESSION_ID" --out evidence.json
lease --from env:DEPLOY_TOKEN --as TOKEN --ttl 5m -- deploy --token-env TOKEN
lease --from vault:secret/data/prod/deploy?field=token --as TOKEN -- deploy --token-env TOKEN
lease --from aws-sm:prod/deploy-token?region=us-east-1 --as TOKEN -- deploy --token-env TOKEN
```

## Security

- **OPA/Rego policies** — every command is evaluated against a policy before execution. Write rules in `~/.adssh/policy.rego`.
- **RBAC entitlements** — YAML-based per-user/group command ACL.
- **Audit log** — every command logged to `~/.adssh/audit.log` (configurable).
- **Restricted mode** — `adssh -r` disables path traversal, cd, export.
- **SSH pubkey and certificate auth** — direct keys and `cert-authority` entries
  in `~/.adssh/authorized_keys`. A direct key line names the accounts it may
  log in as: `user="alice" ssh-ed25519 AAAA...` or `user="alice,bob" ...`; a
  bare key line is refused at startup. A certificate logs in only as one of
  its principals, and a certificate with no principals is refused. Logins as
  root (or any uid 0 account) are refused unless `ADSSH_SSH_PERMIT_ROOT=1`.
  Short-lived user certs can be issued with `identity ssh-ca issue`.
- **Local admin API** (enterprise build, `go build -tags ee`; see `docs/LICENSING.md`) — `admin sessions/gateways/approvals/explain/evidence`
  exposes the current operational state through governed VBINs, and
  `admin serve` exposes the same surfaces over a token-capable local HTTP API.
- **SSH listener jail** — failed handshakes and connection rate on `adssh --serve`
  are counted from `~/.adssh/guard.yaml`. Bans are stored in
  `~/.adssh/guard-state.json`. Manage them with `guard` or with
  `GET /v1/guard` and `POST /v1/guard/unban` on the local admin API.
  See `docs/guard.md`.

Example policy (allow everything except `rm -rf`):
```rego
package adssh.authz

default allow = false

deny {
    input.command == "rm"
    input.args[_] == "-rf"
}

allow { not deny }
```

A decision can also say why. Besides `allow` (bool, required) and
`deny_reason`, a policy may set `required_role`, `rule` (the rule that
decided), and `required_entitlement` (what would allow it). `why`, `??`,
`whoami --caps`, and the `[POLICY]` audit line show them. A `rule` or
`required_entitlement` that is not a string denies. See
`policy/examples/explained.rego` and `docs/site/policy.md`.

Gateway policies can use structured target fields instead of parsing argv:
```rego
allow {
    input.command == "gateway"
    input.gateway.target_host == "bastion.internal"
    input.gateway.target_port == "22"
    input.elevation.role == "prod-admin"
}
```

Lease policies can use structured lease fields before the secret is fetched:
```rego
allow {
    input.lease.source_type == "vault"
    input.lease.ttl_seconds <= 300
    input.lease.destination == "TOKEN"
    input.lease.command[0] == "deploy"
}
```

Starter policy bundles are part of the enterprise layer and live in `ee/policy/bundles/`:

| Bundle | Purpose |
|---|---|
| `home-permissive.rego` | Personal/demo allow-by-default posture |
| `regulated-ops.rego` | Deny-by-default ops with break-glass for production |
| `gateway-only.rego` | Controlled SSH/TCP gateway targets |
| `ai-agent.rego` | Conservative policy for MCP/AI agents |
| `admin-api.rego` | Role-separated admin API operations |

## SSH server

```bash
# Serve on port 2222
adssh --serve :2222

# Or from within Starlark
sys.enable_ssh(address=":2222")

# Connect from another machine
ssh -p 2222 user@host
```

Host key is generated once and persisted at `~/.adssh/host_key`.

## MCP server (AI integration)

`adssh-mcp` exposes adssh as a [Model Context Protocol](https://modelcontextprotocol.io) server, letting Claude and other AI agents drive the shell programmatically.

```bash
adssh-mcp          # starts the MCP server
```

Tools exposed: `eval_starlark`, `run_shell`, `list_sessions`, `cloud_query`, `container_exec`, `audit_log`.

Every MCP request passes through the complete Rego, entitlement, change-management,
four-eyes, restricted-mode, and audit gate with deterministic tool arguments.
The gate also provides structured agent context as `input.agent.id`,
`input.agent.kind`, `input.agent.risk`, and `input.agent.dry_run`. Set
`ADSSH_AGENT_ID` or `--agent-id` to name the agent, and set
`ADSSH_AGENT_REQUIRE_DRY_RUN=true` or `--require-agent-dry-run` to reject
destructive MCP shell plans unless `dry_run=true`.
Within `eval_starlark`, each Go builtin passes through that gate again immediately
before it is called, using an operation name such as
`starlark.docker.images.pull` and canonical `arg0=...`/`keyword=...` policy
arguments. Allowing `eval_starlark` therefore does not implicitly allow its
cloud, container, database, filesystem, networking, or plugin operations.

## Configuration

```bash
adssh --init       # creates ~/.adssh/ with starter files
adssh --doctor     # validates local readiness before using it as a primary shell
```

| Env var | Default | Purpose |
|---|---|---|
| `ADSSH_RESTRICTED` | off | Enable restricted mode |
| `ADSSH_SERVE` | — | SSH server address |
| `ADSSH_GUARD` | follows `guard.yaml` | SSH listener jail switch (`off` forces off, `on` forces on) |
| `ADSSH_GUARD_CONFIG` | `~/.adssh/guard.yaml` | Jail config |
| `ADSSH_GUARD_STATE` | `~/.adssh/guard-state.json` | Ban file |
| `ADSSH_POLICY` | — | Rego policy file path |
| `ADSSH_ENTITLEMENTS` | — | RBAC entitlements YAML |
| `ADSSH_AUDIT_LOG` | `~/.adssh/audit.log` | Audit log path |
| `ADSSH_RECORD_DIR` | `~/.adssh/recordings` | JSONL session recording directory |
| `ADSSH_GATEWAY_LOG` | `$ADSSH_RECORD_DIR/gateway_connections.jsonl` | Gateway connection evidence log |
| `ADSSH_REVOKED_KEYS` | unset | SSH revocation file checked on every login and re-read when it changes. One entry per line: a key, certificate-key, or CA fingerprint (`SHA256:...`), `serial:N`, or `keyid:ID`. When set, a missing or malformed file refuses every login |
| `ADSSH_LOG_LEVEL` | `info` | Listener log level on stderr: `error`, `warn`, `info`, or `debug`. Debug shows each auth attempt, channel request, and session spawn and exit. Logins and sessions are also recorded in the audit chain (`SSH_LOGIN_OK`, `SSH_LOGIN_FAIL`, `SSH_SESSION_START`, `SSH_SESSION_END`) |
| `ADSSH_LOG_FORMAT` | `text` | `text` or `json` |
| `ADSSH_ADMIN_API_KEY` | — | Read-only bearer / `X-ADSSH-API-Key` token for `admin serve` (enterprise build) |
| `ADSSH_ADMIN_KEYS` | — | 0600 `name=key` file; a named key is required to approve, deny or unban, and the name is the audited approver |
| `ADSSH_AGENT_ID` | process-specific MCP ID | MCP agent identity exposed as `input.agent.id` |
| `ADSSH_AGENT_REQUIRE_DRY_RUN` | off | Require `dry_run=true` for destructive MCP shell plans |
| `ADSSH_HISTORY` | `~/.adssh/history` | Readline history |
| `ADSSH_HOST_KEY` | `~/.adssh/host_key` | SSH host key |
| `ADSSH_AUTHORIZED_KEYS` | `~/.adssh/authorized_keys` | SSH pubkeys, each bound with `user="name"` |
| `ADSSH_SSH_PERMIT_ROOT` | off | Allow SSH logins that resolve to uid 0 (`1`/`true`/`yes`) |
| `ADSSH_PROFILE` | `~/.adsshprofile` | Login profile (Starlark) |
| `ADSSH_RC` | `~/.adsshrc` | RC script (Starlark) |
| `ADSSH_AUDIT_URL` | — | Remote audit sink; must be an https URL to a public host (private hosts need `ADSSH_CALLBACK_ALLOW_PRIVATE=1`); requires `ADSSH_AUDIT_LOG` |
| `ADSSH_AUDIT_TOKEN` | — | Bearer token for `ADSSH_AUDIT_URL` |
| `ADSSH_CONTROLPLANE_URL` | — | https origin of the systemapi control plane for `identity device login`; unset fails closed |
| `ADSSH_OIDC_ISSUER`, `ADSSH_OIDC_JWKS_URL`, `ADSSH_OIDC_LOGIN_AUDIENCE` | — | Pinned issuer, https JWKS URL and audience for `identity oidc import`; unset fails closed |
| `ADSSH_OIDC_ADMIN_ISSUER`, `ADSSH_OIDC_ADMIN_JWKS_URL`, `ADSSH_OIDC_ADMIN_AUDIENCE` | — | Same for `--provider admin`; the admin audience must differ from the login audience |
| `ADSSH_CALLBACK_ALLOW_PRIVATE` | off | Allow RFC1918, 100.64/10 and fc00::/7 hosts for the audit, approval-notice and OIDC callbacks |
| `ADSSH_SAH` | off | `1`/`true`/`yes` enables the `sah/1` stdio frame (`adssh sah`) |
| `ADSSH_MAX_SESSIONS` | 128 | Global cap on registered sessions (SSH logins are also capped at 4 per connection and 8 per user) |
| `ADSSH_SESSION_NOFILE`, `ADSSH_SESSION_FSIZE`, `ADSSH_SESSION_CPU_SECONDS` | 256, 1 GiB, 14400 | Hard rlimits applied to each SSH login process; `0` leaves a limit alone |
| `ADSSH_SESSION_NPROC`, `ADSSH_SESSION_AS` | unset (off) | Optional hard rlimits. Off by default: Linux counts NPROC across every thread the user owns, and AS caps reserved address space, so either can abort Go, JVM, or Node programs (adssh included) |
| `ADSSH_GIT_PROMPT` | off | Show the git branch for `\g` in the prompt (`1`/`true`/`yes`/`on`; ignored in restricted mode and SSH sessions) |
| `ADSSH_HIGHLIGHT` | off | Pre-enter danger highlighting (`1`/`true`/`yes`/`on`; needs a terminal and passes the policy gate as `set highlight on`) |

## Plugins

```python
# In your .adsshrc
sys.load_plugin("/path/to/myplugin.so")
plugins["myplugin"].do_something()
```

Plugins implement the `AdsshPlugin` Go interface. See `example_plugin/` for a template.

```bash
go build -buildmode=plugin -o myplugin.so ./example_plugin
```

## License

MIT — see [LICENSE](LICENSE).
