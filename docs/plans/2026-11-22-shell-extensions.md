# Shell, investigation, policy, and SAH extensions

## Existing foundations

- Prompts: `PROMPT`, `RPROMPT`, user/host/directory/time/git escapes, and
  Starlark expressions. See `examples/adsshrc`.
- Customization: Starlark login/RC profiles, emacs/vi keymaps, aliases,
  highlighting, pre/post-command hooks, and registered commands.
- Terminal: `stty` queries, save/restore, sane/raw modes, flags, control keys,
  and size. It only accesses the session's controlling terminal.
- Investigation: `proc`, structured pipelines, `audit`, `evidence`, `why`,
  `whoami`; enterprise adds host, posture, net, disk, and unit surfaces.
- Authorization currently uses Rego, including the gate for Starlark calls.
  There is no existing Starlark authorization-policy registry to toggle.

## Implemented in this change

`filter -r|-s PATTERN FILE`, and session-local `watch set|get|remove hash FILE`
plus `watch list`. See `../investigation.md` for limits and JSON fields.

## Work still required

1. Shell UX: consolidate existing options into discoverable show/set/reset
   commands and named prompt presets. Keep state session-local, validate all
   options before applying, and cover REPL/SSH behavior.
2. Durable file watches: private baseline store, concurrency and crash-safe
   writes, explicit rebaseline authorization, polling lifecycle, change/missing/
   unreadable events, bounded history, and notification rules with cooldowns.
   Keep observation time distinct from filesystem modification time.
3. Starlark policy management: choose additive restrictions versus replacing
   Rego. Proposed interface: `policy list`, `policy show NAME`,
   `policy enable NAME`, `policy disable NAME`. A dedicated, bounded evaluator
   must have no shell/file/network globals. Strict boolean decisions; errors,
   missing decisions, and execution-budget exhaustion deny. Management requires
   administrator authority and auditing; a rule cannot authorize its own
   removal. Listener-side evaluation must cover SSH, MCP, scripts, and REPL.
4. Investigation expansion: agree the required host/process/socket/file
   reports; prefer structured read-only output and explicit platform support.
   Existing scanner demo commands must not be represented as real scanners.
5. SAH/systemapi: choose API management, interactive channels, or both; specify
   whether client lists match inbound authenticated clients, outbound targets,
   or both. Deny entries take precedence; an enabled allowlist denies unknown
   clients. Lists must bind authenticated identities, not request-provided names.
   Use pinned configuration, TLS verification, and existing device-login/token
   semantics. Check the actual server implementation for each endpoint.

Each cross-repository join requires caller and callee changes, end-to-end tests,
and an update to the cross-repository Wired join list. The provisioning →
enrollment → execution handoff remains **not_wired** until those requirements
are met. `admin serve` remains a local API. No binary/module/config rename.
