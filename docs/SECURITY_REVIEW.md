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

## Re-review 2026-10-12 (post hardening)

This section is a later reading of the same tree after the publish-readiness changes. It does not erase the section above. It is not permission to tag. The earlier residual that recordings, elevations, and leases have no HTTP list store is outdated: `GET /v1/recordings`, `GET /v1/elevations`, and `GET /v1/leases` now exist. The earlier sentence that adssh does not run the device flow is outdated: `identity device login` is a client. The earlier sentence that webhook approval links are not done is outdated: `ADSSH_4EYES_WEBHOOK` can send a notice. Those three corrections live here. The original paragraphs stay as the record of that pass.

`math/rand` in `internal/repl/repl.go` still feeds `$RANDOM` only.

### Tests this pass actually ran

From `/Users/ryan/development/adssh`, after the code in this review was written:

- `go test -count=1 -timeout 180s ./security/` passed (18.587s). That package covers the admin HTTP lists, the audit wrapper, lease env/stdin/fd delivery, four-eyes request ids, the approval webhook, `required_role`, device login, and `policy/examples` including `agent-session.rego`.
- `go test -count=1 -timeout 180s ./cmd/adssh-mcp/` passed (4.734s). That package covers the tool allowlist, session binding, dry-run order, and the governed admin and identity tools.
- `go test -count=1 -timeout 180s ./internal/sah/ ./internal/config/ .` passed (`internal/sah` 0.949s, `internal/config` 1.498s, the main package 4.296s). That covers `ADSSH_SAH` off and on.

`scripts/render-homebrew-formula.sh` was run with four 64-hex test digests into `/tmp` and then deleted. A version containing a space, an empty version, and a short digest each exited 2. No rendered formula was left in the repository.

The full module suite was not run. No live dial of the systemapi control plane was made.

### Gateway, lease, recording, elevation, evidence

`gateway start` defaults to `127.0.0.1:0`. Policy runs before the listener opens. `input.gateway` is the structured input. A policy denial of `gateway`, `lease`, or `elevate` may POST a notice. The goroutine discards the webhook error. A discarded error does not authorize the command.

Lease delivery is `env` (default destination `TOKEN`), `stdin`, or inherited fd 3. `--as` is rejected for stdin and fd. The TTL must be greater than zero and at most 24 hours. `policy/examples/lease_bounds.rego` can tighten that to 300 seconds, vault, destination `TOKEN`, and command `deploy`. The secret is not stored on the chain.

Recordings are regular `*.jsonl` files under `ADSSH_RECORD_DIR` or `~/.adssh/recordings`. Symlinks are skipped.

`digest_sha256` on an evidence bundle is the SHA-256 of `json.Marshal` of the selected chain entries, computed before the lease view is attached. Recording references and the gateway log reference are outside that digest. Each recording reference has its own digest of that file.

An empty chain path returns `chain_unavailable` for lease and elevation lists (HTTP 503). A configured path whose file is missing returns an empty list and does not add active-only elevations. A present verified file, including an empty one, includes active in-memory elevations. Verification failure is an error.

### Residuals that remain

The provision, enroll, and execute handoff is not wired. `ADSSH_SAH` defaults off. When it is on, the response field `handoff` is `not_wired`. A frame `lease_id` does not authorize `execute`.

The Homebrew tap repository is not created. No GPG secret is in git. `SHA256SUMS` is signed only when a real Actions run has `secrets.GPG_PRIVATE_KEY`. The SLSA job is pinned to `slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0`. That project’s latest release is v2.1.0 (February 2025) and it is no longer actively maintained. The generic generator attests caller-supplied SHA-256 subjects. The build is not hermetic. The job has not run. `provenance.json` and `slsa-provenance.intoto.json` from `package-release.sh` are local metadata, not a signed attestation. No attestation is checked in.

`docs/site/` is source. It is not a hosted site.

Break-glass `default allow = true` remains. The lease and the `breakglass:open` scope are the authorization. A stolen lease inside its TTL is a shell.

`admin serve` still defaults to `127.0.0.1:8787`. `--listen` can bind a non-loopback address. The API key is then the only authenticator besides `/healthz`.

`identity device login` stores an opaque bearer. It does not import OIDC groups. An Authentik access token is not that bearer. The authorization server stays in systemapi. DNS answers for a non-IP callback host are checked once and can change afterward. A blocked answer or a resolve failure fails closed.

`GET /v1/approvals` still returns `ListPending()`, including the approval token, to a caller who presents the admin API key. Anyone who can read the mode `0600` pending file can read the same token. Operator prompts, webhook bodies, and MCP `admin_list_approvals` do not include it. The public request id is the filename.

This re-review does not authorize a tag.

## Review and remediation 2026-10-16

This section records a third pass over the tree at `aa52990` and the fixes made the same day. It supersedes the earlier sections where they disagree; the earlier text stays as the record of those passes. It is not a tag sign-off.

### How the pass was run

Codex GPT 6.1 reviewed `aa52990` first (`docs/reviews/2026-10-16-codex-review.md`, eight findings). Four further independent reviewers then covered the SSH and process model, authentication and admin surfaces, the grid, plugin, guard and `sys.parallel` subsystems, and the REPL and parser. Every finding below was reproduced with a probe or traced in code before it was fixed. Fixes were made test-first by file group, each with a `Threats:` note and negative tests. The suite contract (`AGENTS.md`, `docs/sah-suite.md`) was checked against the tree: no SAH module imports this module, `handoff` stays `not_wired`, and `admin serve` remains local.

### Corrections to earlier sections

- "`Session.RunShell` runs `GateProgram` before `Runner.Run`" was true, but the gate evaluated the host OS user for any session the embedder created: `BuildPolicyContext` fell back to `os/user.Current()` when the session id was not in the process registry. Fixed: identity is bound on the engine per session, an unknown session id denies, and `set SESSION_ID=` is refused.
- "The admin HTTP handler refuses an empty API key" was true, but the one shared key could approve and deny, and the approver name came from the request body. Fixed: a named key from `ADSSH_ADMIN_KEYS` is required for any decision, the key name is the recorded approver, the body may not carry `approver`, MCP has no approve or deny tool, and every decision is written to the audit chain before the marker file.
- "`GET /v1/approvals` uses `ListPending`" exposed the pending token. Fixed: the public view is returned. The request id is a public handle; the identity authorizes.
- "`DenyRequestAs` uses the same identity checks as approve" was true, but the identity itself could be renamed with `identity device login` against a caller-chosen URL. Fixed: the control-plane origin is pinned by `ADSSH_CONTROLPLANE_URL`, and a renamed session can neither request nor approve.
- The admin listener could bind any address over plaintext. Fixed: loopback or a `unix:` socket only.
- `identity oidc import` accepted `--issuer`, `--jwks-url` and `--discover` from the caller, over `http://`, following redirects, with `exp` optional. A user who served their own JWKS could make themselves eligible for `os-root`. Fixed: issuer, JWKS URL and audience come only from `ADSSH_OIDC_ISSUER`/`ADSSH_OIDC_JWKS_URL`/`ADSSH_OIDC_LOGIN_AUDIENCE` and the `ADSSH_OIDC_ADMIN_*` trio, the fetch is https-only through the callback client, and `iss`, `aud` and `exp` are required.

### Findings fixed in this pass

SSH listener and login process: any enrolled raw key could log in as any user including root (no key-to-user binding, no root switch); a certificate with no principals was valid for every user; a malformed `pty-req` panicked the daemon; handshakes had no deadline and no pre-auth bound; one connection could take every session slot; the login child inherited the listener's whole environment (tokens, root HOME, root's rc file) and the monitor socket on fd 3, and a forged frame written to that fd could desync the gate so a denied command ran while the chain recorded a denial; session rlimits set only the soft limit; Ctrl-C did not reach commands over SSH; session ids were 32-bit and a duplicate silently replaced another session; the gateway authorized a name and dialled whatever it resolved to later.

Enforcement core: `/dev/tcp` and `/dev/udp` redirections dialled with no policy, audit or restricted-mode check at all five runner sites (SEC-1, open since July); a process-wide `wait4(-1)` reaper stole exit statuses from every `exec.Cmd`; two processes sharing one ledger forked the HMAC chain; `ADSSH_AUDIT_URL` was posted to without validation.

REPL: a Starlark expression that failed at runtime was re-run as statements, so side effects ran twice (REPL, `-c`, scripts and `safepaste run`); a leaked terminal reader after each PTY command ate the next typed line; stderr redirection was ignored on the PTY path; the git prompt executed `git status` outside the gate, so a hostile checkout's `core.fsmonitor` ran on every prompt draw; an end-of-paste sequence inside the clipboard released the rest of the paste unfiltered; `exit` inside a `try` block was catchable.

Grid, guard, plugins, parallel: `worktree destroy` removed any directory under a `/tmp` root that could be a symlink, with no elevation; remote peers could cancel local flights; expired flights were never reaped; an agent could clone any readable repository; the guard peer table was unbounded and keyed IPv6 by /128, and a full ban table refused everyone; a failed plugin load left its completer installed; `sys.parallel` ran Starlark custom commands concurrently on shared state and kept running after a denial; forged `ELEVATE_`/`LEASE_` lines typed as commands appeared as evidence.

### SSH login process

Each SSH login is its own process with an empty engine; the listener gates its commands through the monitor socket. This pass found that state-changing virtual binaries (`elevate`, `cm`, `lease`, `grant`, `identity`, `4eyes`, `admin`, `gateway`, `guard`, `grid`, `flight`, `agent`, `worktree`, `repo`, `evidence`, `plugin load`, `mirror kill/view/console`) and the explainers (`why`, `??`) ran in that child against state the listener never saw, and that any local policy evaluation there (`AuthorizeGateway`, `ExplainCommand`, grid rehearse) ran with no policy loaded. In a remote-gate process those names are now refused before dispatch (the listener audits the refusal), every local policy evaluation denies, and the overlay session carries the certificate principals. State-changing operations over SSH need a monitor protocol for state, which is not written.

### Residuals after this pass

- A pending four-eyes wait started over SSH cannot be cancelled from the session before its TTL (default 300s); the monitor `Authorize` frame has no cancel.

- Break-glass from systemapi remains `default allow = true` under a lease; a stolen lease inside its TTL is a shell. Unchanged by design.
- Policy sees `/dev/tcp` hosts by name; DNS resolution happens inside the dial. The gateway now also exposes `input.gateway.target_ip`; the open handler does not.
- A process that still holds fd 3 from before the CLOEXEC fix could replay an allow only for the identical request id and arguments, which policy already allowed.
- `sys.parallel` workers still share the alias and shopt dicts; interactive Ctrl-C does not cancel the Starlark thread.
- The grid code lives in `security/` and should move to `internal/grid`.
- Existing `authorized_keys` files with bare key lines refuse `--serve` until each line carries `user="name"`. This is deliberate and needs a release note.
- Not run: the e2e SSH test as root, and native Linux execution of the terminal and process tests.

### Tests this pass ran

From `/Users/ryan/development/adssh` on Darwin, after every change in this section, with the Go 1.26 toolchain:

- `gofmt -l` clean on all tracked and new Go files; `go vet ./...` and `go vet -tags e2e ./e2e/` clean; `go build ./...`, `make build`, `make build-mcp` clean.
- `go test -count=1 ./...`: every package ok (`security` 54.6s, `internal/starlarkext` 27.6s, `internal/sys` 16.3s, `engine` 16.0s, `internal/repl` 14.8s, `parser` 14.9s, `cmd/adssh-mcp` 9.3s, root 4.5s, `internal/guard`, `internal/safefile`, `internal/config`, `internal/sah`, `internal/agent`, `internal/vbinui`).
- `go test -race -count=1` on `security`, `engine`, `internal/sys`, `internal/repl`, `internal/starlarkext`, `internal/guard`, `internal/safefile`, `internal/config`, `parser`, `cmd/...` and the root package: all ok, no data race reported. `internal/repl` was also run `-race -count=5` because one earlier run under heavy load had failed once; it did not reproduce.
- `go test -tags e2e -count=1 ./e2e/...`: ok (113s). The SSH e2e case skips unless root; it was not run as root.
- A fresh reviewer read the whole diff afterwards; its two seam findings (state-changing virtual binaries in the SSH child, and vbin dispatch reading the mutable `SESSION_ID` global) are fixed above and covered by `security/ssh_remote_refusal_test.go`, `internal/repl/session_binding_test.go`, `cmd/adssh-mcp/tools_shell_test.go` and `main_flow_test.go`.

Not run: native Linux execution of the terminal, signal and wait tests; `sudo make test-e2e`; `govulncheck`.
