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

## Signals & per-session job control — MORE achievable than first stated (corrected 2026-07-18)

Earlier note said "N-session job control needs process separation" — that was too strong. The
PTY substrate already exists: `github.com/creack/pty v1.1.24` is a dep and `sys/ssh.go` gives
every SSH connection its own PTY pair via `pty.Open()`. `sys/job.go:56` already sets
`Setpgid=true` (per-child process group). The reason it's still process-global is a BUG, not a
physics limit:
- `sys/job.go:239` `SetForegroundProcessGroup` calls `tcsetpgrp` on `os.Stdin.Fd()` (the adssh
  process's controlling terminal) instead of the session's PTY slave fd — so `fg`/`bg` from any
  session drive the wrong terminal. Thread the session PTY fd through → per-session fg/bg.
- `sys/signals.go:13-17` is a process-global `signal.Ignore`/`signal.Notify(SIGCHLD)` with one
  global job table. Keep one process-level SIGCHLD reaper but DEMUX to the right session's job
  table via a global PID→session map (PID/PGID known at NewJob).

Kernel already delivers Ctrl-C/Ctrl-Z to the foreground pgrp ON that session's PTY (VINTR/VSUSP
in termios_*.go:54,59), so remote interactive signals are per-PTY for free once the child is in
its own pgrp on that PTY.

Irreducible: the adssh PROCESS has one real controlling terminal, so the locally-launched
single-operator SIGTSTP-suspends-adssh case (repl.go:447) is inherently singular — fine, because
remote sessions don't use the process's controlling terminal.

So TODO(session) #3 becomes: (1) thread session PTY fd through job control instead of
os.Stdin.Fd(); (2) per-session job tables; (3) single SIGCHLD reaper demuxing by PID. All
in-process, enabled by the creack/pty already shipped. Deserves its own focused pass + tests,
separate from the mechanical per-session-state moves (i18n lang, history).

## Starlark enhancement — library additions, same chokepoint

Starlark won't grow `<<<` syntax, but capabilities map to builtins, all routed through the
Engine policy/audit path:
- here-doc/here-string → Starlark native triple-quoted multi-line strings (already there).
- process substitution → `sys.capture()` / temp-fd helper.
- signals → `sys.on_signal(sig, callback)` bridging the trap table.
- network → policy-gated `net.dial()` (exists) + new `net.dial_udp()`; both gated like SEC-1.
