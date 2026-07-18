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

# 6. Session mirroring (pair-program over SSH)
mirror list
mirror view <session_id>
mirror console <session_id>

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
| `mirror` | Live session viewer / console |
| `cmdgen` | Cloud CLI command generator |
| `package` | Cross-platform package manager |
| `proc` | `/proc` filesystem reader/writer (Linux) |
| `grant` | Temporary role escalation |
| `pick` | Charm-powered fuzzy selector for arguments, stdin, or JSON choices |
| `nav` | Interactive three-column file navigator with previews |
| `from` / `where` / `select` / `to` | JSONL structured-data pipeline |
| `why` | Side-effect-free policy/RBAC/CM/four-eyes explanation |
| `runbook` | Typed Starlark runbooks with governed argv-only steps |
| `par` | Bounded parallel execution with per-child authorization |
| `evidence` | Verified, filtered HMAC-chain evidence bundles |
| `lease` | TTL-bounded command-scoped secrets from environment or private files |
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

# Typed Starlark procedures: every step is an argv list and is re-authorized
ADSSH_RUNBOOK_DIR=examples/runbooks runbook run diagnose --param path=. --dry-run

# Parallel child commands are individually policy/RBAC/CM/four-eyes checked
par --jobs 4 api worker scheduler -- printf '%s\n' '{}'

# Export verified audit evidence, or lease a secret to one command only
evidence --session "$SESSION_ID" --out evidence.json
lease --from env:DEPLOY_TOKEN --as TOKEN --ttl 5m -- deploy --token-env TOKEN
```

## Security

- **OPA/Rego policies** — every command is evaluated against a policy before execution. Write rules in `~/.adssh/policy.rego`.
- **RBAC entitlements** — YAML-based per-user/group command ACL.
- **Audit log** — every command logged to `~/.adssh/audit.log` (configurable).
- **Restricted mode** — `adssh -r` disables path traversal, cd, export.
- **SSH pubkey-only auth** — `~/.adssh/authorized_keys`.

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

## License

MIT — see [LICENSE](LICENSE).
