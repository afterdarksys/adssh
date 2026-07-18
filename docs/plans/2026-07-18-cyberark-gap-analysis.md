# Competitive gap analysis — adssh vs CyberArk (PAM)

**Logged:** 2026-07-18. **Status:** strategy note, not scheduled work.
**Framing:** adssh is NOT a CyberArk clone (CyberArk = heavyweight PAM suite around a hardened
credential vault). Do not chase feature parity — it erases adssh's identity (programmable,
policy-as-code, AI-native, cryptographic audit). Close the 3-4 PAM gaps that are buyer table-stakes
while leaning into the differentiators.

## Where adssh already wins (don't undervalue)
- HMAC hash-chain = cryptographically tamper-EVIDENT audit; better compliance primitive than
  CyberArk session logs.
- Rego/OPA policy-as-code — more expressive than CyberArk's policy model. Four-eyes + CM gating
  (ServiceNow/Jira) already shipped.
- Programmability (Starlark) + AI-native (MCP operator) — no CyberArk equivalent. The real moat.
- Session mirroring foundation (mirror.go / OutputBroadcaster).

## Real gaps that matter to a PAM buyer (ranked by strategic fit)
1. **Credential injection / zero-knowledge secret use** — THE one most missing. CyberArk PSM's
   crown jewel: operator runs a privileged command but NEVER sees/holds the credential (injected at
   exec, never in terminal/scrollback/history). adssh's secrets.* does the opposite (reads into
   session). Natural fit: adssh already controls the exec path AND the output path; dovetails with
   the secret-redaction backlog item. HIGHEST LEVERAGE.
2. **Session recording + live monitor + kill.** Full keystroke/output record tied to the audit
   chain + supervisor watch/terminate. mirror.share() backlog item extended.
3. **Directory/SSO integration** — AD/LDAP, SAML/OIDC, SCIM. adssh is pubkey-only (authorized_keys).
   Enterprise table-stakes; can't sell into a CyberArk account without it.
4. **Credential vaulting: rotation + checkout/checkin + JIT lease** — be a vault, not just read one.
   `elevate --for` backlog is the JIT/zero-standing-privilege seed.
5. **Behavioral analytics + auto-response** — anomaly detection on sessions, auto-suspend. Audit
   chain is perfect raw material; on-brand for the AI-native angle.
6. **Access certification + compliance reporting** — attestation campaigns + SOC2/PCI/SOX reports
   off the audit chain. The chain is the moat; reporting monetizes it to auditors.

## Deliberately DO NOT chase (different product; imitating loses)
Estate-wide privileged-account discovery/onboarding; Endpoint Privilege Manager (local-admin removal);
hundreds of legacy platform connectors (mainframe/network-gear); clustered hardened-vault appliance.

## Highest-leverage move
Credential injection / zero-knowledge secret use (#1) + session-record-and-kill (#2). Both extend
machinery adssh already owns (every command intercepted, every output byte controlled) rather than
starting new product lines — and let adssh sit in a PAM conversation while keeping policy-as-code /
AI-native differentiation.
