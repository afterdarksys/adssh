# Handoff for Claude

Written 2026-10-26, refreshed 2026-11-08. A fresh session can act from this file alone. Homes for lookups are named below; read those files instead of trusting a copy. Trust git over any sha here.

**State (2026-11-08).** `main` matches `origin/main` at `7f2795f` ("feat: add per-user SSH and TCP proxy destinations"). Before it, `ea0dc47` added the emergency sash path (`ADSSH_SASH_EMERGENCY`, `internal/sashparent`). CI run 42473789385 on `7f2795f` failed: golangci-lint (HTTP 502 in the action, infrastructure), `internal/sashparent` tests (they build `../sash/cmd/sash`, and `afterdarksys/sash` on GitHub is empty), and macOS e2e (300 s timeout). The last green run is 40273745327 on `b6cb0e5`. The host door is stopped. `internal/sah/sah_ee.go` still has `Handoff = "not_wired"`.

## Next

1. CI on `main` (2026-11-08): the enterprise golangci-lint findings in the proxy files are fixed, and the e2e harness build limit went from 5 to 15 minutes (a cold macOS cache exceeded 5). `afterdarksys/sash` was pushed (public, `b43dc49`, gitleaks and trufflehog clean, no LICENSE file yet); the test job clones it at that pinned sha into `../sash` for `internal/sashparent`. Bump the pin in `.github/workflows/ci.yml` when sash changes.
2. Proxy audit (fixed 2026-11-08): `PROXY_RESULT` is accepted only against a pending authorization from `resolveProxy` in the same session (cap 64, reserved before the allow audit line, dropped on session unregister). The shell refuses typed `proxy _resolve`/`_result`, including via `command`/`exec` (`refuseTypedInternal`). Governed children (`par`, `runbook`, `lease`) are refused too (`runGovernedCommand`). Child-side failures after a resolve report `failed`.
3. Product code beyond those, a tag and a host copy wait for Ryan to ask.

The lease-handoff decisions (`sah/2`, no client repair, exact `cmd`) are now recorded in the Decisions section of `docs/plans/2026-10-16-lease-handoff-design.md`; key delivery is still open there. Legacy authentication (no shadow, LDAP or Kerberos on the listener) is `docs/plans/2026-11-06-legacy-auth.md`. Deploy stays stopped (Ryan chose "Stop here" on 2026-10-26). `ADSSH_SAH_REQUIRE_LEASE` stays off until the `sah/2` change.

## What is already on main

The feature commit is `de72f0b`. The file list is `git show --stat de72f0b`. It merged with `--no-ff` as `e7ccdca`. Two later commits are on main and pushed:

- `756cea0` is gofmt only (`security/policy.go`, `security/ssh_monitor.go`). Run [40271865742](https://github.com/afterdarksys/adssh/actions/runs/40271865742) on `e7ccdca` failed golangci-lint for format. No behavior change.
- `b6cb0e5` is test-only (`internal/grid/grid_hardening_ee_test.go`). Run [40272966099](https://github.com/afterdarksys/adssh/actions/runs/40272966099) on `756cea0` failed `TestGridReaperExpiresFlightsWhileListening` under `-race -tags ee`. Cancel is published under the lock; the agent session is unregistered after unlock. The test now waits until the flight is canceled and `sys.GetSession` is nil. Production order in `reapExpiredFlights` stays.

Rechecked while writing this file: run 40273745327, status completed, conclusion success, headSha `b6cb0e5f7c2bdae30dcf2fb7af7f7a4448b97248`. The Ubuntu 26 runner-image notice is an annotation. Root SSH e2e runs on ubuntu via sudo and is skipped on macOS.

## Local binaries

`dist-linux/` is gitignored (`.gitignore`). These are static enterprise builds from 2026-10-26, `CGO_ENABLED=0`, `GOOS=linux`, `GOARCH=amd64`, `-tags ee`, `-ldflags "-s -w -X main.version=v0.10.0-4-g756cea0"`. They are stripped ELF x86-64. They are not a signed release, not installed, and not a tag. The version string names `756cea0`; production behavior matches `b6cb0e5` because that commit is test-only.

| File | SHA-256 |
|---|---|
| `dist-linux/ready-756cea0/adssh` (112M) | `b80a4bb9a06be724fdb0bf145e4bf62d8afbc985a7f4a998b14fe89e2f87bc13` |
| `dist-linux/ready-756cea0/adssh-mcp` (112M, enterprise rebuild) | `8d98d9011572a41bffa7097bfe6aef864b31557a69af72980f46e150119d813d` |
| `dist-linux/ready-756cea0/adsshadm` (7.0M) | `0399c4ba50bdeb33fe89ebd66a7ce648029581e9f5e29098822b60c81a83ea67` |

An earlier core build of `adssh-mcp` (`8e748736cd00c566a61afe980e6eb55629adc9662c60aef739232149f2cdd7b6`) was overwritten. Reconfirm with `shasum -a 256 dist-linux/ready-756cea0/*` before any copy. Copying waits for a new door decision.

## Read these, do not copy them

- How the shell is built: `CLAUDE.md`. Admin-plane text is in the security-layer paragraph and the env list. The SAH suite section is the `## SAH suite` heading. Leave that section alone. `AGENTS.md` wins on suite membership; `CLAUDE.md` wins on how the shell is built.
- Suite contract: `docs/sah-suite.md` and `~/development/systemapi.io/docs/sah-suite.md`. A cross-repo call ships only when the caller, the callee, and both Wired joins change together.
- Lease design: `docs/plans/2026-10-16-lease-handoff-design.md`. The Enrollment section is the piece that is nobody's yet. The Decisions list is stale on carrier and `cmd_prefix` until Ryan says to edit it.
- Roadmap: `docs/plans/2026-10-16-roadmap-execution.md`. Wave G is this handoff. Wave F (cloud gaps) is a separate unstarted list.
- Host beta, a different checklist: `docs/plans/2026-10-16-secure-beta.md`. Item 3 is dr1, adssh on `127.0.0.1:2222` over Ryan's tunnel, with `[R]` approving each door step.
- Crypto, tokens, TLS, SQL, randomness, or password hashing: read `~/development/ads-fable-utils/SECURITY-RULES.md` before editing. Done when the change has a `Threats:` note and a negative test that rejects tampered, expired, oversized, or wrong-key input and fails closed.
- Gate order: `gateCommandContext` in `security/interceptor.go`. Empty args become nil before the admin plane. The managed-agent allowlist and expiry run before Rego and before the budget.
- Break-glass: `docs/systemapi-embed.md`. It stays a child process.

## Guardrails

Each rule is the thing to do, then the check, then why.

1. Keep `Handoff = "not_wired"` until systemapi issues leases only for an enrolled host and a scoped principal, computeapi enrollment writes `ADSSH_SAH_HOST_ID` and `ADSSH_SAH_LEASE_KEYS` mode 0600, each repo has its tests, and both Wired joins are edited in that same change. Check: `grep Handoff internal/sah/sah_ee.go` still prints `not_wired`, and `docs/sah-suite.md` is untouched. Starting the issuer, enrollment, or `sah/2` inside adssh alone leaves the callers and the suite contract behind the code.
2. Fleet writes go through `vpsexec` / `vpscfg` in `~/development/vpscfgfarm`. Leave miniapps1 alone (Debian 12, 108.165.123.119, tenant afterdark). A host copy waits until Ryan names the door again. dr1 (108.165.123.9) is Debian 10, `eol: true`, and production. builder1 is the manual Linux test host; `scripts/linux-ci-builder1.sh` prints `vpsexec` steps and does not run them. The operator types each line, reads the plan, then repeats with `--run --approve=<plan-hash>`. No adssh runbook exists in the estate. `install.sh` is a local sudo installer to `/usr/local/bin`, which is the laptop path.
3. A release tag waits until Ryan asks. Check: `git tag --points-at HEAD` is empty. The 2026-10-12 security re-review does not authorize a tag. Homebrew tap publish is still pending (`f5666d5`). `.github/workflows/release.yml` publishes a GitHub release on tags `v*`. Dispatching it would publish.
4. Keep the names `adssh`, `adssh-mcp`, module `github.com/afterdarksys/adssh`, config `~/.adssh`, and repo `afterdarksys/adssh`. A brand edit that renames them breaks the Go module path. GitHub would redirect the repo. The module path would not.
5. Keep `admin serve` as the loopback admin API. Describe it that way. A public admin API or SFTP, or a second systemd, package manager, or container runtime, would advertise or duplicate a surface this repo does not own. TCP forwarding exists only in the enterprise build: `gateway`, SSH `direct-tcpip` and `proxy`, all gated by policy and, when `ADSSH_PROXY_CONFIG` is set, by the per-user destination list (`docs/proxy.md`). Without that variable native forwarding is gated by Rego alone.
6. Keep the emergency path narrower than allow-all. A frame `lease_id` does not authorize a command. `ADSSH_SAH_REQUIRE_LEASE` stays off until the handoff is wired. An allow-all emergency path would skip the policy that the lease is only a necessary condition for.
7. Leave TLS verification on. `identity oidc import` verifies an already-issued OIDC JWT via JWKS. Pointing it at the device-login bearer would accept a token the importer does not check. Device login stays in systemapi `controlplane/oauth.js`.
8. Enterprise files stay `//go:build ee`. The core build (`//go:build !ee`) keeps compiling. `main.go` does not import `grid`. The comment near `main.go:29` ("grid registers the grid, flight, agent, worktree, and repo vbins.") is orphaned; leave it. `make test` is `go test ./...` with no `-tags ee`. `make build-ee` is the enterprise shell.
9. Export a security symbol only when `main` or `grid` must call it. The existing set is `RunRecovery`, `AsofAt`, `LiftQuarantine`, `BindAgentBudget`, `ClearAgentBudget`, and `AgentBudget`. `AgentAllowlist` (`security/roles.go`) already returns a copy of `agentAllow` (worktree, repo, runbook, par, why, ??, evidence, lease). Leave `do`, `unit`, and `host` off that list. Adding them would let an agent run host admin verbs the allowlist was built to refuse.
10. Before a test matrix, unset `ADSSH_QUARANTINE`, `ADSSH_QUARANTINE_FILE`, `ADSSH_SAH_REQUIRE_LEASE`, `ADSSH_REFUSE_ALLOW_ALL`, `ADSSH_HOST_PROFILE`, `ADSSH_HOST_PROFILE_PREV`, `ADSSH_HOST_PROFILE_KEYS`, `ADSSH_HOST_PROFILE_NARROW`, `ADSSH_HOST_ID`, `ADSSH_AGENT_UNIT`, `ADSSH_ADMIN_LISTEN`, `ADSSH_SAH_LEASE_KEYS`, `ADSSH_SAH_ISSUER`, `ADSSH_SAH_HOST_ID`, and `ADSSH_SAH_LEASE_STATE`. The dev machine is macOS. Tests pass without root and without a live systemd. Skip `t.Parallel` on tests that touch quarantine env, `closeRead`, `doRun`, `doEuid`, `doLookup`, `unitRun`, `unitInvoke`, `journalRun`, `hostChmod`, `netRun`, `netShow`, `diskRun`, `walkClose`, or the budget map. `t.Setenv` is fine. Packages `security`, `internal/grid`, and `internal/sah` do not use `t.Parallel`. A leaked env var fails a matrix that would pass in CI.
11. If Ryan asks for a commit: one sentence subject, a short body, author Ryan Coleman `<coleman.ryan@gmail.com>`, no AI attribution trailer. Commit this file only after he asks. A commit he did not ask for lands on `main` that CI will build.

## Traps that are not in CLAUDE.md

These are why a second edit in the same package failed once. Read the test before changing it.

**Sessions and names.** A second `adminFix` in one test calls `UnregisterSession` first; the error is `adssh: session id is already registered`. The host-profile tamper helper is `tamperHostSig` because `tamperSig` already exists. Admin-plane tests use `bytesOf`. `TestUnitMissedTimerReturnsRawAudit` has no unused `ctx`; the second `LogEvent` returns the raw audit error.

**Lease and policy strings.** `CommitLeaseJTI(dir, jti, exp int64, now time.Time)` takes `exp` as `int64`; `time.Unix` is the wrong conversion. `sahLeaseStateDir` does not nest under `adssh`. The first call consumes `jti` even when authorize denies; the second is `lease_replayed`. `VerifyExecLease` does not consume the `jti`. Lease errors are exactly `lease_required`, `lease_rejected`, `lease_expired`, `lease_replayed`, or `lease_command_mismatch`. A SAH deny of `["/bin/echo","hi"]` is `adssh: access denied for '/bin/echo' by policy`. The string `adssh: access denied: policy: deny by default (no allow decision)` appears only when the result object has no `allow` field. Untagged tests do not call `SetAdminPlane`.

**Platform.** On macOS, `do` is not euid 0; tests inject `doEuid`. `asof` rejects a decoy `PrevHash` and a zero 32-byte key before the walk. Alias `sudo` requires `--`, then sudo maps to `do`. `apt` is always refused. A quarantine file lift does not clear the quarantine env. `AuthorizeCommand` uses `context.Background()`, so `WithRecover` is invisible on that path; package-refuse tests call `vb.Run(WithRecover(ctx))`.

**Reaper.** `reapExpiredFlights` marks the flight canceled, unlocks, then `releaseAgentSessions`. One poll can see a canceled flight whose session is still registered. Wait until both are true.

## Deferred, and when

- Record `sah/2`, no FIXUP, and exact `cmd` in the plan's Decisions section. When Ryan says to edit that file. Until then this handoff is the record and the plan stays as it is.
- The three-repo handoff (systemapi issuer, computeapi enrollment, `sah/2`, both Wired joins). When Ryan starts that change and the three repos move together.
- Tag, `secrets.GPG_PRIVATE_KEY`, the SLSA run, and the Homebrew tap repo. When Ryan asks. Tap publish is still pending at `f5666d5`.
- A host. When Ryan names a door again. The 2026-10-26 choice was stop. The ready artifact is `dist-linux/ready-756cea0/`.
- Secure-beta P0/P1 and Wave F. When a later request names those lists. They are separate from the admin plane.

## Close

```
git rev-parse HEAD
git status --short --branch
gh run view 40273745327 --json conclusion,headSha,status
```

Done when HEAD is `b6cb0e5f7c2bdae30dcf2fb7af7f7a4448b97248`, that run's conclusion is `success`, and you stop.
