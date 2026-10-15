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

`admin serve` listens on `127.0.0.1:8787` unless `--listen` is set. `--listen` can bind a non-loopback address. The API key is then the only authenticator besides `/healthz`.

Routes: `/healthz`, `/v1/sessions`, `/v1/gateways`, `/v1/approvals`, `/v1/approvals/approve`, `/v1/approvals/deny`, `/v1/explain`, `/v1/evidence`, `/v1/recordings`, `/v1/elevations`, `/v1/leases`, `/v1/guard`, `/v1/guard/unban`. The schema is `docs/openapi/admin.yaml`.

The SSH listener jail counts failed handshakes and connection rate on `adssh --serve`. `GET /v1/guard` reports the effective config and active bans. `POST /v1/guard/unban` removes one ban. The operator document is `docs/guard.md`.

`/healthz` is unauthenticated and is not audited. Every other request is audited with method, path, status, and the SHA-256 fingerprint of the API key. The body and the query string are not logged. An empty API key is refused. The compare hashes both sides with SHA-256 and then compares the digests.

`GET /v1/approvals` returns the pending request, including the approval token, to a caller who presents the admin API key. The same token is stored in a mode `0600` file under `~/.adssh/foureyes/pending`. MCP `admin_list_approvals` does not serialize that token.

## Identity

`identity oidc import` verifies an already-issued OIDC JWT. It does not accept the opaque device-login bearer.

`identity device login` is a client of systemapi `controlplane/oauth.js`. It writes the bearer to a mode `0600` file, prints the path and a SHA-256 fingerprint, and sets the session user with no groups. An Authentik access token is not that bearer. The authorization server stays in systemapi. Dashboard login stays Authentik.

The client requires TLS 1.3 and the system CA pool. It refuses non-HTTPS URLs except the literals `127.0.0.1` and `::1`, refuses redirects, and refuses link-local and metadata addresses. DNS answers are checked once. A later change of those answers is not re-checked.

## Approval

A new four-eyes request stores a secret token inside the `0600` JSON file. The public request id is the filename. Operator prompts and webhook payloads use the request id and a fingerprint of the token. They do not print the token.

`ADSSH_4EYES_WEBHOOK` receives a JSON notice when a four-eyes request is created, and when policy denies `gateway`, `lease`, or `elevate`. Other denials do not send a notice. `ADSSH_APPROVAL_LINK_BASE` may add an `approval_link`. A discarded webhook error does not authorize the command.
