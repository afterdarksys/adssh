# Backlog — "Controlled I/O" wave (shell parity + network egress)

**Logged:** 2026-07-17 (from a feasibility discussion). **Status:** backlog, not scheduled.
**Sequencing:** after the current finish-line pipeline (negative tests → session items →
errcheck → `internal/` boundary → `v0.9.0`). The `/dev/tcp` fix (SEC-1) may be pulled
*forward* into the session wave because it's the same "route through the Engine" refactor.

Lead with the security fix, not the features — that's the on-brand deliverable.

## SEC-1 (headline / real bug): network egress bypasses the enforcement core

`security/openhandler.go` already implements bash's `/dev/tcp/host/port` and
`/dev/udp/host/port` by calling `net.Dial` **directly** — no `EvaluatePolicy`, no
`BuildPolicyContext`, no `LogCommand`, no audit-chain entry. The OpenHandler is a hole
straight through the policy/audit chokepoint the overhaul just hardened. In a security-first
shell this is the classic reverse-shell / exfil vector, unguarded.

Fix: make the OpenHandler an `(*Engine)` method (mirroring `BashInterceptorSession`) that runs
the same policy → CM/4-eyes(optional) → audit gate before dialing, so Rego can allow/deny
egress by host/port and every connection is logged in the hash chain. Negative tests:
denied host blocked and audited; connection logged; restricted mode blocks raw `/dev/tcp`.

Related: `starlarkext/net.go:88` hardcodes an `InsecureSkipVerify` path in `dial_tls` — a
banned pattern under the repo security rules (rule 5). Fold into the same pass: default to
verify, require an explicit, audited opt-in (or drop it).

## Shell parity (mostly verification + tests, inherited from mvdan.cc/sh v3.13.1)

The embedded interp already parses/executes these; work is proving they survive the REPL and
stay audited, not implementing them.

- **Here-strings (`<<<`), here-docs (`<<EOF`)**: confirm the REPL line-reader feeds a complete
  open-heredoc block to the parser (multi-line continuation). `-c`/script paths already work.
- **Process substitution (`<(cmd)` / `>(cmd)`)**: relies on `/dev/fd`; inner commands run in
  the same runner so they already pass back through `BashInterceptor` (audited). Add an E2E
  test proving the inner command is policy-checked.
- **Brace/param expansion, `trap`**: already present; add coverage.

## Signals — partial, bounded by one controlling terminal

Already have SIGTSTP self-suspension, SIGCHLD, SIGHUP, `trap` + `__traps__`. Full support ties
into TODO(session) #3. Achievable: per-session trap tables, per-session job table. NOT
achievable in-process: independent real POSIX job control for N SSH sessions (needs process/PTY
separation). Document the boundary; don't fake it.

## Starlark enhancement — library additions, same chokepoint

Starlark won't grow `<<<` syntax, but capabilities map to builtins, all routed through the
Engine policy/audit path:
- here-doc/here-string → Starlark native triple-quoted multi-line strings (already there).
- process substitution → `sys.capture()` / temp-fd helper.
- signals → `sys.on_signal(sig, callback)` bridging the trap table.
- network → policy-gated `net.dial()` (exists) + new `net.dial_udp()`; both gated like SEC-1.
