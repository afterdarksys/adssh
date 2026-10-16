# adssh code review for Claude

Date: 2026-10-16  
Reviewed commit: `aa5299020a0bece4e8e9e793caa2f1254daf978a`

Two independent agent reviewers took the requested perspectives: senior Go developer for macOS/Linux, and senior macOS/Linux security engineer specializing in Go. The coordinating reviewer verified the embedding identity issue and consolidated the findings. This is a review, not a remediation patch. No product code was changed.

## Assessment and validation

Eight actionable findings are below, ordered by priority. Address the SSH identity and daemon-crash issues before relying on this implementation as a privileged multiuser SSH service. Existing passing tests do not cover the demonstrated failure cases.

- `make test` (`go test ./...`): PASS, all tested packages.
- `go vet ./...`: PASS.
- Native environment: Darwin/amd64, Go module target 1.26.0.
- Targeted temporary test overlays reproduced raw-key username impersonation, duplicate Starlark execution, abandoned terminal input consumption, stderr redirection loss, and competing child reaping.
- A standalone public-API program reproduced incorrect session identity during authorization.
- PTY request panic and missing handshake limits were established through code inspection; no daemon crash or resource exhaustion attack was performed.
- Linux shares the relevant source paths, but native Linux execution, race testing, exhaustive cloud integration testing, and dependency vulnerability scanning were not performed. This is not a claim of exhaustive security coverage.

Repository guidance consulted: `AGENTS.md`, `CLAUDE.md`, `docs/sah-suite.md`, and `../ads-fable-utils/SECURITY-RULES.md`.

## Findings

### 1. P1 / Critical: A directly authorized SSH key can authenticate as any username, including root

**Locations:** `internal/sys/ssh.go:118–122`, `internal/sys/ssh.go:328–352`, `internal/sys/session_limits.go:74–102`.

The direct-key fallback checks membership in a single global key set, but never binds that key to `conn.User()`. The client-selected username becomes the session identity, and the child credential code resolves and applies that account's Unix UID/GID. UID 0 is accepted. The SSH listener is intended to run as root.

**Prerequisites and impact:** Possession of any enrolled raw private key allows impersonation of another resolvable local account. With the default allow-all policy and a functioning session launch, this includes root execution. Policies based on username also receive the impersonated identity. Certificate authentication is a separate path; this finding concerns directly enrolled raw keys.

**Evidence:** A temporary test called the real `publicKeyCallback` with the same enrolled key and usernames `alice`, `bob`, and `root`; all were accepted. Credential application was verified in source, rather than by launching a root shell.

**Fix:** Bind raw keys to explicitly permitted usernames, or require certificates with validated user principals. Add an independent root-login policy. Refuse mismatches before session creation.

**Regression tests:** A key enrolled for Alice must fail for Bob and root. An unlisted key must fail. A permitted principal-bound certificate should still work, and wrong/expired principals must fail closed.

### 2. P1 / High: Malformed SSH PTY requests panic the entire daemon

**Location:** `internal/sys/ssh.go:367–370`.

The request handler indexes `req.Payload[3]` without a length check and slices at `termLen+4` without checking the remaining payload. An authenticated client can open a session and send an empty or truncated `pty-req`. The unrecovered goroutine panic terminates the listener process and disconnects other sessions. The terminal string length is also decoded as one byte instead of the protocol's uint32.

**Prerequisites:** A successful SSH authentication and a resolvable username. No shell command permission is needed to reach the request parser.

**Evidence:** Directly reachable unchecked indexing and slicing in the request goroutine. `parseDims` checks its own input, but is called only after the unsafe access.

**Fix:** Decode the complete request with `ssh.Unmarshal` into a correctly typed structure. Reject malformed or oversized requests before touching the PTY.

**Regression tests:** Empty payload, truncated string, inconsistent length, and truncated dimensions must be rejected while the daemon stays alive. Use a subprocess or integration test so a panic cannot silently escape the assertion.

### 3. P1 / High: Public engine sessions authorize as the host user instead of SessionOptions.User

**Locations:** `engine/session.go:136–150`, `engine/session.go:171–174`, `security/policy.go:262–286`.

`NewSession` stores `opts.User` in the returned struct but does not supply it to authorization. `BuildPolicyContext` looks up the session ID in the process-global internal session registry; when absent, it silently falls back to the OS user and groups. Creating a session through the public embedding API does not register that identity. External embedders also cannot directly import this module's `internal/sys` package to repair the omission.

**Impact:** A host that creates an untrusted user's session under an administrator/service account can grant the host account's policy rights to that session. If an ID happens to resolve in the global registry, it can instead use that unrelated identity. This contradicts the public API's documented per-session identity/isolation contract.

**Reproduction:** Create an engine whose policy allows only `input.user == <current OS username>`. Open a session with `User: "untrusted-review-user"` and an unregistered session ID, then call `RunShell(ctx, "echo identity-check")`. Observed:

```text
declared_user=untrusted-review-user host_user=ryan execution_error=<nil>
```

**Fix:** Carry authenticated identity and groups explicitly in session authorization state, scoped to the owning engine. Fail closed for missing required identity rather than borrowing the process identity. Ensure shell commands, declaration gates, and Starlark-backed operations agree on the same principal.

**Regression tests:** The reproduction must be denied. Sessions for two users must get their own decisions; equal session IDs in separate engines must not cross identities.

### 4. P1 / High: Runtime-failing Starlark expressions execute their side effects twice

**Location:** `internal/repl/repl.go:164–175`.

`evalStarlark` retries the source with `starlark.ExecFile` after any `starlark.Eval` error. Runtime errors can occur after side effects have already happened. For example, `mutate() / 0` calls `mutate` in the first evaluation and again in the fallback. Infrastructure mutations, notifications, or commands can be duplicated.

**Evidence:** Targeted test supplied a counting builtin and evaluated an expression that fails after calling it. The count was 2.

**Fix:** Decide expression versus statement syntax before execution. Fall back only for the relevant parse failure; never retry code after runtime evaluation has begun.

**Regression tests:** A side-effecting builtin followed by an evaluation error must be called exactly once. Valid statements and successful expressions must retain their intended behavior.

### 5. P1 / High: Completed interactive commands leave terminal readers that consume subsequent input

**Location:** `internal/repl/pty_exec.go:154–158`.

The detached `io.Copy(ptmx, tty)` can remain blocked on the real terminal after the child exits. Closing its destination PTY does not cancel the source read. When the user enters the next command, the abandoned reader can consume it and then discard it on a failed write to the closed PTY. It competes with the line editor and subsequent commands.

**Evidence:** A test ran a short-lived child, then wrote `after-exit\n` and `second-line\n` to the parent terminal. The next explicit terminal read returned only `second-line\n`; the abandoned copy consumed the first line.

**Fix:** Give terminal input forwarding an explicitly cancellable lifetime and finish it before returning to the prompt, without closing the shared controlling terminal. Also give the SIGWINCH forwarding goroutine a shutdown path: `signal.Stop` alone does not close its channel.

**Regression tests:** Repeated short commands must leave no competing reader; the first line entered after each exit must reach the prompt intact. Check goroutine lifetime as well.

### 6. P2 / Medium: Interactive PTY execution ignores stderr redirection

**Locations:** `internal/repl/pty_exec.go:74–93`, `internal/repl/pty_exec.go:111–132`.

PTY eligibility checks stdin and stdout but ignores stderr. The command's stderr is never assigned from `hc.Stderr`, so `pty.Start` attaches it to the PTY. A command such as `sh -c 'echo SECRET >&2' 2>errors.log` writes the message to the terminal/session output instead of the requested file. This also risks recording material the operator intended to redirect.

**Evidence:** Targeted test observed `redirected stderr="" stdout="SECRET\r\n"`.

**Fix:** Preserve redirected stderr when launching the child, or exclude separately redirected stderr from PTY wrapping.

**Regression tests:** Verify `2>file`, `2>/dev/null`, and intentional `2>&1` behavior in an interactive terminal.

### 7. P2 / Medium: Global SIGCHLD reaping steals exit statuses from os/exec

**Locations:** `internal/sys/signals.go:15–21`, `internal/sys/signals.go:37–40`; installed at `main.go:187`.

The signal goroutine calls `Wait4(-1, ...)` for all children, competing with `exec.Cmd.Wait`. If it wins, it consumes the child's exit status; for children outside the global job table, that status is discarded. The actual owner gets `wait: no child processes` instead of the real exit code. Foreground commands, SSH children, and other subprocess users can be affected.

**Evidence:** With `SetupSignals` active, a test started `sh -c 'exit 7'`, allowed signal handling, then called `cmd.Wait()`. It received `*os.SyscallError: wait: no child processes` instead of an exit error containing code 7.

**Fix:** Establish one wait owner per process. Do not globally reap children owned by `os/exec`; route completion from that owner into job tracking.

**Regression tests:** Concurrent short-lived foreground/background children must preserve exact success, nonzero exit, and signal statuses with signal handlers enabled.

### 8. P2 / Medium: Unfinished SSH handshakes retain resources indefinitely

**Location:** `internal/sys/ssh.go:284–298`, particularly `ssh.NewServerConn` at line 292.

The server starts a goroutine for each accepted connection but sets no handshake deadline or bound on simultaneous unauthenticated handshakes. An unauthenticated peer can hold connections open without completing SSH. The admission guard limits arrival rate, but slow arrivals can remain below it while accumulating connections. These connections do not reach handshake outcome accounting or authenticated session limits.

**Impact:** Eventual file descriptor/goroutine/memory exhaustion without an enrolled key.

**Evidence:** Listener and guard control flow inspection. No resource exhaustion test was run.

**Fix:** Set a bounded network deadline for handshake/authentication and clear it after successful authentication. Bound concurrent pre-authentication connections and release the slot on every exit path.

**Regression tests:** A stalled handshake must close within the configured timeout. Filling pre-auth slots must not exhaust the listener, and completing/closing a handshake must release its slot.

## Additional conditional concern

`internal/sys/session_child.go:15–16,38–85` scans every process argument for `--session-child` in package initialization and execs the supplied command tail before main initializes policy, audit, or restricted mode. This can also trigger when the marker is passed as an ordinary script argument. A deployment that uses adssh as a restricted command wrapper while allowing caller-controlled arguments needs an explicit trust boundary for this internal launch mode. The current SSH request handler does not directly expose that argv path. This was not counted among the eight primary findings because the security impact depends on the deployment's invocation contract. Check and test that contract during remediation.

## Handoff and reproduction artifacts

Temporary probes from this review (not committed, and not durable regression coverage):

```sh
go test -overlay /tmp/adssh_review_overlay.json ./internal/repl -run '^TestReview' -count=1 -timeout=30s
go test -overlay /tmp/adssh_review_overlay.json ./internal/sys -run '^TestReview' -count=1 -timeout=30s
go test -overlay /var/folders/sg/hcn9jmd14dj4cf_rd72jnc180000gn/T/adssh-security-review-hobk2ua4/overlay.json ./internal/sys -run TestReviewDirectKeyAcceptsArbitraryUsername -v
go run /tmp/adssh-review-identity.go
```

The four correctness regression probes intentionally FAIL on current behavior, demonstrating findings 4–7. The direct-key probe passes while demonstrating acceptance of all three usernames. Probe sources: `/tmp/adssh_review_test.go`, `/tmp/adssh_review_sys_test.go`, and the security overlay's temporary directory. Reproduction expectations are described above so fixes do not depend on these temporary files surviving.

For remediation, preserve the repository/module/binary names and suite boundaries. Security changes require a `Threats:` note and negative fail-closed tests under the repository instructions. Run touched-package tests and `make test`; validate terminal/process fixes natively on both macOS and Linux. No fixes or commits were made as part of this review.
