# Backlog — syntax highlighting + private sessions (control-plane design)

**Logged:** 2026-07-18. **Status:** backlog, not scheduled.

**Design principle (applies broadly):** match the control plane to the concern.
Cosmetic/operational preferences → CONFIG toggles (ADSSH_* + `set`). Anything touching
authorization, audit, or visibility → REGO, so it's centrally governable per environment.

## Syntax highlighting (config-toggleable) — feasible via existing machinery
- Mechanism: reuse the chzyer/readline `Listener` hook already used for fish-style
  autosuggestions (repl/listener.go adsshListener.OnChange). Return the line with ANSI color
  codes injected. Token tables already exist in the completer (shellBuiltins,
  starlarkNamespaces, vbin list); parser.DetermineMode gives Starlark-vs-shell.
- Control plane: COSMETIC → config, not Rego. ADSSH_HIGHLIGHT env / AppConfig field + runtime
  `set` option, per-session (fits Session model).
- UNIFY with operator-DX #3 "danger highlighting pre-enter" — same line-colorizer subsystem
  (color rm -rf / DROP / --force red). Build once, get both.
- Caveats: as-you-type coloring via readline Listener is fiddly (cursor math, wide chars);
  MVP fine, "flawless" may later want a dedicated editor (go-prompt lexer). Output highlighting
  (color jq/JSON output) is a separate, easier post-process.

## Universal private sessions (Rego-managed) — feasible, with one non-negotiable
- Mechanism: sessions exist in all three paths (local REPL, SSH, MCP) and carry per-session
  state post-extraction; PolicyContext conveys session info. Add a `private` session mode
  (adssh --private / sec.private_session() / SSH flag) exposed to Rego as a checkable action or
  field (input.action == "session.set_private" or input.session.private).
- Per-environment management = the point: enterprise default.rego denies it; home/permissive
  allows it. Same binary, behavior by policy file.
- **NON-NEGOTIABLE (security):** "private" = reduced VISIBILITY/RECORDING, NEVER unaudited.
  The HMAC chain still records that a private session occurred; HOW MUCH it may suppress
  (metadata-only / redacted commands / full commands) is itself a Rego decision, so policy sets
  the floor even when private mode is allowed. Otherwise it's an audit hole that kills the value
  prop. "Private" controls mirror/scrollback/list_sessions visibility + secret echo, not the
  ledger's existence.
- Dovetails with: session recording + live-monitor/kill (CyberArk gap #2), secret redaction
  (operator-DX #2), whoami --caps / ?? (so a user knows if private mode is available).
