# File investigation commands

`filter` and `watch` are portable in-process commands, available through normal
shell execution and MCP `run_shell`. The shell applies its existing policy,
entitlement, and audit checks before dispatch.

## Filter text

```sh
filter -s 'authentication failed' /var/log/auth.log
filter -r '^error: (timeout|refused)' application.log
```

Print matching lines; do not edit the input. String matching is literal and
case-sensitive. Regex matching uses Go's regular-expression syntax. A valid
search with no matches succeeds with empty output. Files must be regular,
no larger than 64 MiB; lines are limited to 1 MiB and patterns to 64 KiB.
Final-component symlinks, devices, and FIFOs are refused. Output is streaming:
an error later in the file can follow already-emitted matches. Check the exit
status before treating output as complete.

## Track hashes

```sh
watch set hash ./config.yaml
watch get hash ./config.yaml
watch list
watch remove hash ./config.yaml
```

This is an adssh-specific command, not Unix `watch` (periodic command execution).
`set` explicitly establishes or replaces a SHA-256 baseline. `get` computes a
fresh hash, emits JSON, and fails with a nonzero status if the content differs.
It never automatically accepts a changed file as the new baseline. `list`
returns the last recorded observations without reading the files again.
Relative paths resolve against the shell's current directory.

JSON records contain `path`, `sha256` (baseline), `current_sha256`, `match`,
`set_at`, `checked_at`, `changed_at` (when observed), `modified_at` (filesystem
mtime), and `size`. Timestamps are UTC. `changed_at` is the last observed
non-baseline content transition, not the exact time a write occurred; restoring
the baseline retains that history. Missing, oversized, or unreadable files fail
without replacing the last successful observation.

Baselines are **in memory**, keyed by engine and session ID, with a maximum of
1024 files per engine. They do not survive a process restart. Remove unused
baselines explicitly. These commands do not schedule polling or send external
notifications. JSON and the mismatch exit status are building blocks for rules:

```sh
watch get hash ./config.yaml > observation.json || echo 'Check tracked file'
```

The failure branch also covers read and policy errors: inspect the error rather
than assuming every nonzero exit means changed content.

Threats: bounded regular-file reads reject final symlinks, devices, FIFOs, and
oversized input. Hashes detect changes relative to a trusted observation; they
do not protect against an attacker controlling the shell process or OS account.
Parent symlinks are resolved by the OS. Hashing checks size and mtime before and
after reading but does not provide a filesystem snapshot. File operations use
the process's OS permissions; this is not a filesystem sandbox.
