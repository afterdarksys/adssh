# adssh — North Star / Positioning

**Logged:** 2026-07-18 (Ryan's articulation). The one-liner the roadmap ladders up to.

> **CyberArk meets fish meets a lovingly-built, programmable DevOps shell** — for regulated
> environments, but genuinely fun to use at home. Same binary; behavior set by policy.

## Three layers (every feature belongs to one)
1. **Governance spine (CyberArk-grade).** Policy-as-code (Rego), tamper-evident HMAC audit chain,
   four-eyes, change-management gating, deny-by-default enforcement, and — coming — credential
   injection / zero-knowledge secret use, session record + live-monitor/kill, private sessions
   (visibility mode with a policy-set audit floor). This is the moat + what makes it sellable
   into regulated shops.
2. **Delight layer (fish-grade UX).** Fish-style autosuggestions (have), syntax highlighting +
   danger highlighting (backlog, one colorizer), `??` deny-explainer, `confirm`/destructive
   preview, `whoami --caps`. Makes it a shell people WANT to use, not just tolerate.
3. **Power layer (programmable).** Extended Starlark — quasi-familiar to Python devs — over the
   full cloud/k8s/db/secrets/notify namespaces, custom commands, plugins, and AI-native operation
   via MCP. The reason it replaces glue scripts, not just bash.

## The dual-audience mechanism
Same binary, two postures, decided by the POLICY FILE (+ config for cosmetics):
- **Regulated:** restrictive default.rego — private sessions off or fully-audited, egress gated,
  four-eyes on destructive ops, everything in the chain.
- **Home / permissive:** no policy or an open one — private sessions, unrestricted, highlighting
  on, all the fun, none of the friction.

Control-plane rule (see highlighting/private-sessions doc): cosmetic → config; anything touching
authorization/audit/visibility → Rego.

## Roadmap docs this anchors
- CyberArk gap analysis (credential injection = headline gap)
- Controlled-I/O wave (SEC-1 /dev/tcp gating, shell parity, network builtins)
- Operator-DX batch (?? / redaction / danger-highlight / confirm / elevate / mirror.share / whoami)
- Highlighting + private sessions (control-plane design)
- Session internals + per-session job control (creack/pty), x/term, go-acl
