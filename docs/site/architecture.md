# Architecture

adssh is the execution shell. It owns policy, the HMAC audit chain, four-eyes approval, break-glass recording, native SSH when policy allows it, and the local `admin serve` HTTP API.

## Suite boundary

The other names stay in their own repositories.

| Name | Role |
| --- | --- |
| opensah | Local index: `version`, `tools`, `ready`. Not a platform. |
| sahconnect | Calls systemapi over HTTP. `ssh` execs the `adssh` binary and adds no arguments. |
| sahapi | Loopback allowlisted GET proxy. OAuth does not live here. |
| sahlink | Captures stdin, stdout, and stderr of a program the operator starts. Optional loopback relay. It does not attach to a PID and it does not ptrace. |
| sahcore | Unassigned. Docs only. No binary. |
| systemapi | Linux control plane, outbound agent, CLI, and dashboard. |
| computeapi | On-demand compute catalog. Vast.ai and io.net are the wired compute adapters. |

No SAH module imports `github.com/afterdarksys/adssh`. The systemapi agent does not import adssh. Break-glass is a child process. See `docs/systemapi-embed.md`.

The handoff "computeapi provisions, the machine enrolls through systemapi, adssh executes under a lease" is a design. It is not wired. `ADSSH_SAH` does not perform it.

## Two host paths

An in-process host imports `github.com/afterdarksys/adssh/engine`. Construction fails closed on malformed Rego. A zero `engine.Config` is allow-by-default and has no audit chain. Production hosts set `RequirePolicy` and a chain key. See `docs/EMBEDDING.md`.

systemapi starts adssh as a child. The break-glass policy is `default allow = true` so the HMAC chain records the session. The control-plane lease and the `breakglass:open` scope are the authorization. A stolen lease inside its TTL is a shell.

## Local admin API

`admin serve` listens on `127.0.0.1:8787` unless `--listen` is set. `--listen` accepts a loopback IP, a hostname whose every address is loopback, or `unix:/absolute/path`. `0.0.0.0`, `::`, an empty host, and any non-loopback address are refused. A Unix socket is created mode `0600` in a directory that is owned by the user, is not a symlink, and grants no group or other access. An existing path is refused unless it is a socket nobody answers on. The server sets read, write, idle, and header timeouts and caps request bodies at 1 MiB.

Approvers authenticate with named keys. `ADSSH_ADMIN_KEYS` (or `--keys-file`) names a mode `0600` file of `name=key` lines, owned by the user and opened without following a symlink. A name matches `[A-Za-z0-9_.-]{1,64}`. A key is at least 32 bytes with no whitespace. A duplicate name or key refuses the file. The matching key's name is the request's principal. It is the only approver identity `POST /v1/approvals/approve` and `/deny` use. A body that sends `approver` gets 400. `POST /v1/guard/unban` also needs a named key.

`ADSSH_ADMIN_API_KEY` (or `--api-key`, `--api-key-env`) is the legacy shared key. It reads sessions, gateways, approvals, explanations, evidence, recordings, elevations, leases, and guard status. It gets 403 on approve, deny, and unban.

Routes: `/healthz`, `/v1/sessions`, `/v1/gateways`, `/v1/approvals`, `/v1/approvals/approve`, `/v1/approvals/deny`, `/v1/explain`, `/v1/evidence`, `/v1/recordings`, `/v1/elevations`, `/v1/leases`, `/v1/guard`, `/v1/guard/unban`. The schema is `docs/openapi/admin.yaml`.

The SSH listener jail counts failed handshakes and connection rate on `adssh --serve`. `GET /v1/guard` reports the effective config and active bans. `POST /v1/guard/unban` removes one ban. The operator document is `docs/guard.md`.

`/healthz` is unauthenticated and is not audited. Every other request is audited with method, path, status, the SHA-256 fingerprint of the presented key, and the principal (`bob`, `legacy`, or `none`). The body, the query string, and the key are not logged. `ADMIN_HTTP_START` records each key name with a fingerprint prefix. An empty key is refused. Each presented key is compared against every configured key by hashing both sides with SHA-256 and comparing the digests in constant time.

`GET /v1/approvals` returns public request ids. It does not return the stored token. MCP `admin_list_approvals` returns the same view.

## Identity

`identity oidc import` verifies an already-issued OIDC JWT. It does not accept the opaque device-login bearer.

`identity device login` is a client of systemapi `controlplane/oauth.js`. It writes the bearer to a mode `0600` file, prints the path and a SHA-256 fingerprint, and sets the session user with no groups. An Authentik access token is not that bearer. The authorization server stays in systemapi. Dashboard login stays Authentik.

The client requires TLS 1.3 and the system CA pool. It refuses non-HTTPS URLs except the literals `127.0.0.1` and `::1`, refuses redirects, and refuses link-local and metadata addresses. DNS answers are checked once. A later change of those answers is not re-checked.

## Approval

A four-eyes request is a mode `0600` JSON file named by its request id, 32 random hex characters. The request id is a public handle, not a credential. Prompts, `4eyes pending`, and `GET /v1/approvals` show it. A legacy token field is still stored in the file and is never shown.

A decision is authorized by the approver's identity. On HTTP that is the named admin key. In the shell it is the session user, only when the code that registered the session set it (the local shell or an SSH login). A session renamed by `identity device login` or any other runtime identity change cannot approve or deny. A verified OIDC import can, once it marks the session `oidc-verified`. Agent sessions cannot decide. MCP has no approve or deny tool, and `adssh-mcp` refuses every decision in its process, including `4eyes approve` through `run_shell`. The requester cannot decide their own request. A rule's configured approver must match.

A decision claims the pending file by atomic rename, so one approve or deny wins and the other gets "already decided". It then writes `FOUREYES_DECISION request=<id> approver=<name> decision=approve|deny surface=http|shell|api` to the audit chain. Only after that write succeeds is the approved or denied marker written. If the audit write fails, the claim is put back and no marker is written.

`ADSSH_4EYES_WEBHOOK` receives a JSON notice when a four-eyes request is created, and when policy denies `gateway`, `lease`, or `elevate`. Other denials do not send a notice. `ADSSH_APPROVAL_LINK_BASE` may add an `approval_link`. A discarded webhook error does not authorize the command.
