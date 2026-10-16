# Roadmap execution — started 2026-10-16

Order of work after the 2026-10-16 remediation. Each wave is a set of file groups that
do not overlap, so they run in parallel. A wave is done when its packages pass
`go test -race`, the gate (`gofmt`, `go vet`, `make test`, `make test-e2e`) is green, and a
separate reviewer has read the diff.

## Wave 1 (in repo)

| Group | Scope | Files |
|---|---|---|
| A | SSH state protocol: run state-changing virtual binaries in the listener on the child's behalf over the monitor socket (frames for vbin run, output, exit, cancel). Lifts the "not available in an SSH session" refusal for non-interactive vbins and makes a four-eyes wait cancellable. Plugin dir reaches the child as an argv flag. | internal/sys/monitor_frame.go, security/ssh_monitor.go, security/interceptor.go (remote branch), ssh_session.go, internal/sys/ssh_spawn.go, main.go (starter) |
| B | Move the grid to `internal/grid` with the engine injected; `loadFlightCA` through `internal/safefile`. | security/grid.go, security/vbin_grid.go → internal/grid |
| C | Shell: delete the orphaned job table and its builtins, REPL Ctrl-C cancels the Starlark thread, pre-enter danger highlighting, `confirm` / destructive preview, bounded signal handling. | internal/sys/job.go, internal/repl/* |
| D | Policy output: matched rule and required entitlement in the decision; `why`/`??` show them; `whoami --caps`; `mirror.share()`. | security/policy.go, explain.go, vbin_why, new vbins, mirror.go |
| E | Starlark stdlib: `data.validate`, `data.assert_type`, `str.slugify`, `str.template`, `log.*` (audit-bound), `net.dial_udp`; `sys.parallel` per-worker alias/shopt copies; here-doc and process-substitution gate tests. Every new builtin is gated or provably pure. | internal/starlarkext/* (new files), go.mod |

## Wave 2

- F: cloud gaps — `gcp.gke`, `gcp.pubsub`, `gcp.run`, `aws.cloudwatch`, `aws.route53`, `notify.teams`.
- G: the provision → enroll → execute handoff. Design is in `~/development/systemapi.io/docs/sah-suite.md`; ships only with a test and an edit to the Wired join list there. Cross-repo; needs the lease format from systemapi.

## Needs the operator

- Tag, GPG (`secrets.GPG_PRIVATE_KEY`), SLSA run, Homebrew tap repo. Release notes are in CHANGELOG.
- Linux coverage comes from GitHub CI (race + coverage on ubuntu-latest on every push); `scripts/linux-ci-builder1.sh` is the manual fallback through the fleet door.
- Nothing: the root-only SSH e2e case now runs in CI on ubuntu via sudo.
