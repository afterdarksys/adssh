# Backlog — shell config parity (mostly DONE; gaps + security invariant)

**Logged:** 2026-07-18. **Status:** backlog. Most of this ALREADY EXISTS.

## Already implemented (verified in code)
- `~/.adsshprofile` (login) + `~/.adsshrc` (interactive), full Starlark; ADSSH_PROFILE / ADSSH_RC
  overrides (internal/config/env.go:61-62).
- System-wide `/etc/adssh_profile` loads (internal/config/profile.go:21).
- Prompt: expandPrompt bash/zsh-style escapes (\u \h \w \t ...), RPROMPT (right prompt),
  multi-line continuation (internal/repl/repl.go:245,536,541).
- Aliases/unalias, history + `!!` expansion, preexec/postcmd hooks, trap, set -e/-u/-x/-o
  pipefail, pushd/popd/dirs, tab completion, fish-style autosuggestions.
- Stronger than a normal shell: rc is real Starlark (functions, SDK calls, logic in config).

## Gaps to add for full parity + the regulated story
1. **System-wide interactive rc** (`/etc/adssh/rc`) to complement /etc/adssh_profile — enterprise
   ships org defaults (prompt, aliases, banner) for every session.
2. **Documented config layering / precedence:** system profile -> system rc -> user profile
   (login) -> user rc (interactive) -> ADSSH_* env -> CLI flags.
3. **SECURITY INVARIANT (make explicit + test):** rc/profile are CONVENIENCE ONLY — they set
   prompts/aliases/functions but can NEVER escalate privilege, because every command still passes
   the interceptor + Rego regardless of rc contents. This is WHY "customize freely at home, locked
   down at work" is safe: config is cosmetic, policy is authoritative, separate planes. Add a
   negative test: an rc cannot bypass a deny policy (e.g. rc defines an alias/function for a denied
   command -> still denied + audited).
4. Minor: customizable continuation prompt (PS2-equivalent); restricted-mode note on what rc may do
   (restricted already omits dangerous builtins/namespaces).

Ties to north-star: config plane (cosmetic) vs Rego plane (authoritative) — see
2026-07-18-highlighting-and-private-sessions.md control-plane rule.
