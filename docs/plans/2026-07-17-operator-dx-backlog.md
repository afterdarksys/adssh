# Backlog — Operator DX & break-glass batch

**Logged:** 2026-07-17. **Status:** backlog, not scheduled.
**Theme:** turn the enforcement core (Rego + RBAC + audit chain + mirror) into operator-facing
UX. Most of these are *reads* of machinery that already exists — high value, low build cost.
Sequencing: after the finish-line pipeline; several pair naturally with the controlled-I/O wave.

Ranked roughly by value-to-effort (author's take in parens).

## 1. `??` — "why was I blocked?"  (highest DX win, small)
After any policy denial, `??` prints the exact Rego rule that stopped you + the role/approval
that would unblock it. Turns "permission denied" into "here's why, here's the fix."
- Fit: needs the interceptor to stash the last `EvaluatePolicy` decision (rule path + deny_reason
  + PolicyContext) in the session; `??` formats it. Rego already returns `deny_reason`; extend the
  policy result to also surface the matched rule name / required entitlement.
- Dependency: cleanest after the session wave (per-session "last denial" state).

## 2. Auto-redaction of secrets in output + history + audit *display*
Token/key-shaped strings scrubbed from scrollback, history, and printed audit — real value stays
only in the encrypted chain. Kills "I pasted a secret, now it's in three logs."
- Fit: uniquely feasible because adssh owns the output path (Session I/O writers). Add a redacting
  `io.Writer` wrapper on session stdout + a history-write filter + a display filter on audit export.
- Care: pattern-match (JWT, AWS AKIA, PEM, high-entropy) with allowlist; NEVER alter what's written
  to the HMAC chain (redaction is display-only, or the chain stores a fingerprint — decide explicitly).
  Overlaps SEC-1's "don't log secrets" rule. Threats note required.

## 3. Danger highlighting pre-enter
REPL flags `rm -rf`, `DROP`, `terminate`, `--force`, force-push in red before Enter. A speed bump
where you want one.
- Fit: readline/prompt-render hook in `repl/`; pure client-side, no policy change. Cheap.

## 4. `confirm` builtin / destructive preview
`aws.ec2.terminate(...) | confirm` queries current state, shows what would actually die, requires
`y`. Leverages existing cloud namespaces.
- Fit: a shell builtin + Starlark helper that introspects the piped op's target and dry-run-describes
  it. Depends on each cloud verb exposing a "describe target" path; start with EC2/ECS/k8s delete.

## 5. `elevate --for 10m --reason "..."` — break-glass lite
Time-boxed privilege bump, auto-logged, auto-drops when the timer expires. No standing elevation.
- Fit: session-scoped temporary entitlement injected into `PolicyContext.Groups` (or a `claims`
  field) with an expiry; interceptor checks expiry each command; grant + auto-drop both hit the audit
  chain. Pairs with #7. Rego reads the elevation claim to widen `allow`.
- Dependency: session wave (per-session elevation state); audit chain (already there).

## 6. `mirror.share()` — live session invite
`sys/mirror.go` + `OutputBroadcaster` already exist. Expose a verb to invite a second operator to
watch read-only in real time. On-call handoff / incident bridge, nearly free.
- Fit: mostly wiring — a Starlark/shell verb that registers a viewer against the existing broadcaster
  and prints a join token/endpoint. Auth the viewer via the same pubkey/authorized_keys path.

## 7. `whoami --caps`
"What am I allowed to do right now, in this session, under current policy." Reads RBAC + Rego and
prints live capabilities. Saves trial-and-error.
- Fit: evaluate the loaded Rego against the session's `PolicyContext` over a set of representative
  actions (or use Rego partial-eval to enumerate allows); merge with entitlements. Non-trivial to make
  exhaustive — start with "explain my groups + which known verbs are allowed/denied."
- Pairs with #1 (#1 explains a *specific* denial; #7 previews the *whole* surface).

## Cross-cutting
- #1, #5, #7 all want richer Rego output (matched rule, required entitlement) — do that policy-result
  extension once, use it three ways.
- #2, #5 are security-domain: `Threats:` header + negative tests (redaction can't leak; elevation
  can't outlive its TTL; both fail closed).
