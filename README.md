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

## Starlark namespaces

| Namespace | What it does |
|---|---|
| `aws` | EC2, S3, ECS, Lambda |
| `gcp` | Compute, Storage |
| `oci` | Compute, Storage |
| `git` | clone, status, add, commit, push, pull, log |
| `github` | repos, PRs, issues, releases, workflows |
| `containers` | exec (audited), list, audit, replay, clean |
| `data` | json_parse/dump, yaml_parse/dump |
| `sys` | exec_cmd, exec_async, read_file, write_file, getenv, load_plugin |
| `net` | tcp_send, http_get |
| `crypto` | md5, sha256 |
| `re` | match (RE2), pcre_match |
| `sec` | audit, is_restricted, file_hash, check_policy |
| `i18n` | load, set_lang, T |

## Virtual binaries

Built-in tools that work without installing anything. Type `vbins` to list them all, `<name> --help` for usage.

| Binary | Description |
|---|---|
| `jq` | JSON processor |
| `yq` | YAML processor |
| `http` | HTTP GET client |
| `mirror` | Live session metadata, viewer, console, and audited termination |
| `admin` | Local admin API for sessions, gateways, approvals, evidence, and explanations |
| `identity` | OIDC identity import and short-lived SSH certificate issuance |
| `cmdgen` | Cloud CLI command generator |
| `package` | Cross-platform package manager |
| `proc` | `/proc` filesystem reader/writer (Linux) |
| `grant` | Temporary role escalation |
| `elevate` | Time-boxed break-glass elevation with reason and audit trail |
| `gateway` | Policy-audited local TCP gateway for SSH and internal services |
| `pick` | Charm-powered fuzzy selector for arguments, stdin, or JSON choices |
| `nav` | Interactive three-column file navigator with previews |
| `from` / `where` / `select` / `to` | JSONL structured-data pipeline |
| `why` | Side-effect-free policy/RBAC/CM/four-eyes explanation |
| `??` | Explain the last blocked command in the current session |
| `runbook` | Typed Starlark runbooks with governed argv-only steps |
| `par` | Bounded parallel execution with per-child authorization |
| `evidence` | Verified, filtered HMAC-chain evidence bundles |
| `lease` | TTL-bounded command-scoped secrets from environment, private files, Vault, and cloud secret managers |
| `darkscan` | Simulated malware-scanner demo (no security verdict) |
| `memforensics` | Simulated memory-forensics demo (no process inspection) |

### Advanced VBIN workflows

```bash
# Fuzzy terminal selection and navigation
printf 'dev\nstaging\nproduction\n' | pick --query prod
nav ~/src

# Structured pipelines remain ordinary POSIX byte streams (JSONL internally)
cat services.json | from json | where 'row["cpu"] > 50' | select name,cpu | to table

# Explain governance without executing or opening an approval request
why -- kubectl delete namespace production
??   # after a denied command, explain what blocked it

# Import externally verified OIDC claims into this session, then inspect admin state
identity oidc import --env ADSSH_OIDC_TOKEN --issuer https://idp.example --audience adssh
identity status
admin sessions --json
admin gateways
admin approvals
admin explain -- gateway start --target bastion.internal:22

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
  in `~/.adssh/authorized_keys`; short-lived user certs can be issued with
  `identity ssh-ca issue`.
- **Local admin API** — `admin sessions/gateways/approvals/explain/evidence`
  exposes the current operational state through governed VBINs.

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

Starter policy bundles live in `policy/bundles/`:

| Bundle | Purpose |
|---|---|
| `home-permissive.rego` | Personal/demo allow-by-default posture |
| `regulated-ops.rego` | Deny-by-default ops with break-glass for production |
| `gateway-only.rego` | Controlled SSH/TCP gateway targets |
| `ai-agent.rego` | Conservative policy for MCP/AI agents |

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
| `ADSSH_POLICY` | — | Rego policy file path |
| `ADSSH_ENTITLEMENTS` | — | RBAC entitlements YAML |
| `ADSSH_AUDIT_LOG` | `~/.adssh/audit.log` | Audit log path |
| `ADSSH_RECORD_DIR` | `~/.adssh/recordings` | JSONL session recording directory |
| `ADSSH_GATEWAY_LOG` | `$ADSSH_RECORD_DIR/gateway_connections.jsonl` | Gateway connection evidence log |
| `ADSSH_AGENT_ID` | process-specific MCP ID | MCP agent identity exposed as `input.agent.id` |
| `ADSSH_AGENT_REQUIRE_DRY_RUN` | off | Require `dry_run=true` for destructive MCP shell plans |
| `ADSSH_HISTORY` | `~/.adssh/history` | Readline history |
| `ADSSH_HOST_KEY` | `~/.adssh/host_key` | SSH host key |
| `ADSSH_AUTHORIZED_KEYS` | `~/.adssh/authorized_keys` | SSH pubkeys |
| `ADSSH_PROFILE` | `~/.adsshprofile` | Login profile (Starlark) |
| `ADSSH_RC` | `~/.adsshrc` | RC script (Starlark) |

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
