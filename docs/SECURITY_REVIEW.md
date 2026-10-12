# adssh defensive security review

Date: 2026-10-12. This is a reading of the current tree plus the tests named below. It is not a release sign-off, a penetration test, or an exploit write-up.

## What this pass checked

Tests run from `/Users/ryan/development/adssh` this session:

- `go test ./internal/starlarkext/ -run SkipVerify` passed.
- `go test ./security/ -run 'AdminHTTP|FormatAdminHTTP|FourEyes_Timeout|FourEyes_Approve'` passed.
- `go test ./security/ -run TestPolicyExamplesCompile` passed. That loads the three new examples through `NewEngine`. It does not evaluate decisions.
- `go test ./engine/ -run 'RunShell|RunStarlark'` passed.

The full module suite was not run. No live dial of the systemapi control plane was made.

## Controls that hold

Starlark `http_get`, `tcp_send`, and `dial_tls` refuse `skip_verify` before any dial, including when `ADSSH_ALLOW_INSECURE_TLS=1`. TLS configs set `MinVersion` to TLS 1.3. They do not pin certificates and they do not replace the system root pool. Responses are capped at 1 MiB. `internal/starlarkext/net.go`.

The admin HTTP handler refuses an empty API key. `/healthz` stays unauthenticated. The key compare hashes both sides with SHA-256 and then compares the 32-byte digests. The start line prints `auth=token` or `auth=refused-empty-key` and does not print the key. The audit event stores a boolean, not the key. `security/admin_http.go`, `security/vbin_admin.go`.

`POST /v1/approvals/approve` calls `ApproveRequestAs`, which rejects self-approval and a wrong configured approver. An empty required approver means any distinct approver. `GET /v1/approvals` uses the handler's engine `ListPending`.

`Session.RunShell` runs `GateProgram` before `Runner.Run`, so `export` does not skip the gate. `RunStarlark` runs on the session thread. `print` is not a policy decision. `sys["exec_cmd"]` is gated by `resolveExecParams`, which uses the session engine when one is set. A caller that runs `Runner.Run` directly still skips `RunShell`.

A loaded policy that errors, omits `allow`, or returns a non-bool `allow` denies. No policy loaded allows, unless `RequirePolicy` refused to construct the engine. `security/policy.go`.

`math/rand` in `internal/repl/repl.go` feeds shell `$RANDOM` only. It is not used for keys, nonces, or approval tokens.

## Residuals

Break-glass from systemapi writes `package adssh.authz` / `default allow = true` and starts `adssh` with no `-r`. The control-plane lease and the `breakglass:open` scope are the authorization. The allow policy exists so the audit chain records the session. A stolen lease inside its TTL is a shell. `systemapi-agent/pty.go`.

`DenyRequestAs` uses the same identity checks as approve: a non-empty approver, no self-deny, and a match when the rule names an approver. A failed check leaves the pending file in place. The admin API key is still required to reach the HTTP route. When the rule names no approver, any distinct non-requester who holds that key can deny.

Recordings, elevations, and leases have no HTTP list store. OpenAPI and MCP parity for the new admin and identity operations are not done.

`admin serve` defaults to `127.0.0.1:8787`. `--listen` can bind a wider address. The API key is then the only authenticator besides `/healthz`.

Zero `engine.Config` is allow-by-default and has no audit chain. Production hosts need `RequirePolicy` and a chain key. `docs/EMBEDDING.md`.

`docs/plans/2026-07-17-controlled-io-wave-backlog.md` still says `starlarkext/net.go` hardcodes `InsecureSkipVerify`. The code no longer does. The plan line is stale. This review did not rewrite the plan.

Follow-up PTY frames (`pty_input`, resize, stop) are not re-leased after `pty_start`. A second `pty_start` replaces the active session. The kill timer is `expiresUnix`. See `docs/systemapi-embed.md`.

## Not claimed

Homebrew tap, GPG release signing, and keyless SLSA provenance are not done. The systemapi control plane has username-first device login. adssh still only imports OIDC JWTs and does not run that flow. Webhook approval links are not done.
