# Secure beta checklist (started 2026-10-16)

Goal: an adssh build Ryan can put on a real host, log into over SSH, administer with adsshadm, and trust the record of. Each item lands on a branch with tests and a review pass. [R] marks a decision or action only Ryan can take.

## P0: needed before anyone else touches it

1. **Operational logging.** Structured `log/slog` in the SSH listener. `ADSSH_LOG_LEVEL=error|warn|info|debug` (default info), `ADSSH_LOG_FORMAT=text|json` (default text), to stderr for journald. Every line carries the remote address and, once known, the session id and login name. Debug shows the handshake, each auth attempt and its result, channel types and requests, and session spawn and exit (pid, code, duration). Session children never log operationally: their stderr is the user's terminal.
2. **Login and session audit events** in the hash chain: `SSH_LOGIN_OK`, `SSH_LOGIN_FAIL` (rate-limited per source so scanners cannot flood the chain), `SSH_SESSION_START`, `SSH_SESSION_END`. Each carries the key or certificate fingerprint, certificate serial, key id and principals, the source address, and the end reason and exit status. A failed audit write refuses the login (fail closed). Fingerprints only: never key material, environment values, or terminal bytes.
3. **Real-host test on dr1**: adssh bound to 127.0.0.1:2222 and reached over Ryan's SSH tunnel, so dr1's firewall does not change. Covers key login, certificate login, refused logins, session limits, `adsshadm sessions` and view-only `snoop`, audit verify, and `ADSSH_LOG_LEVEL=debug` output. Cleanup goes through a committed runbook. [R] approves each door step.
4. **Certificate revocation.** A revoked-keys file (`ADSSH_REVOKED_KEYS`: key fingerprints and certificate serials or key ids) checked on every auth, fail closed if the file is unreadable. Without it a leaked certificate lives until it expires.
5. **Default `.adsshrc` error.** `set_keymap` is called before the REPL defines it, so every new install prints "Error loading profiles".
6. **Security review of the login path** (auth callback, certificate checks, session spawn, privilege drop, monitor socket, attach) by a separate reviewer, after items 1, 2 and 4 land.

## P0 for internet-facing (security review of 9bbece9, 2026-10-16)

The review verdict: OK for a loopback-only beta on one host where every key and certificate is bound to a named human account, no principal doubles as a role or system account, and the testers are trusted with forwarding. Not OK for internet-facing until these land:

- **R1 (high)**: honour certificate extensions. Refuse a session channel without `permit-pty` and refuse direct-tcpip without `permit-port-forwarding`; honour `no-port-forwarding` on raw keys; make the gateway deny unless the policy has an explicit gateway rule.
- **R2**: principals are both login names and policy groups. Filter privileged role names (`FilterUnprivileged`) before `BindSessionIdentity`, and separate groups (a cert extension or a `group:` prefix) from login names.
- **R3**: refuse accounts that are nologin or false, locked, or expired, and uids below `UID_MIN` unless allowlisted.
- **R4**: `--session-child` runs from `internal/sys`'s init in every importing binary (a broad sudo rule becomes a root shell). Move it into adssh's main and require a listener-only marker.
- **R5**: DoS caps: pre-auth connections per source, connections per user, and a deadline before `shell`.
- **R6**: document that the chain records commands the session reports. Offer auditd for a complete execve record.
- Low: behind a tunnel every source is 127.0.0.1 (guard and addr= lose the real source); a raw key bound to several names gives one person several four-eyes identities.

## P1: before a public beta announcement

7. **Licensing before any public release.** Waves 2 and 3 of the open-core split still sit in core: four-eyes, change management, evidence, elevate/grants, leases, identity/SSH CA, gateway, grid. A release tagged before they move ships them under Apache 2.0 for good. [R] wait for waves 2 and 3, or knowingly ship them as core. Also [R]: the legal entity name and a lawyer's read of the ee/LICENSE grant.
8. **Release pipeline**: [R] Ed25519 signing key and `GPG_PRIVATE_KEY` secret, enterprise tarballs (wave 3), Homebrew formula for the core, and attestations verified on a test tag.
9. **Install guide and hardened systemd unit**: config layout, host key, authorized_keys and cert-authority lines, revocation file, logging, the admin socket in an owner-only directory, and known limitations (no cgroups, no host certificates, no certificate options).
10. **Flaky root-package test**: one run took 28 s and one failed once under a full parallel run. Find it before CI starts failing at random.
11. **CI runner move**: GitHub moves `ubuntu-latest` to Ubuntu 26 on 2026-10-19. Watch the first run.

## P2: after beta

12. Per-session cgroups (pids.max, memory.max) as the real replacement for the NPROC/AS rlimits.
13. Host certificates (the server presents a CA-signed host key).
14. Certificate critical options (`source-address`, `force-command`).
15. Command-name registries (listener Run table, `internal/sah`), so the core build stops naming enterprise commands.
16. Rename `adminGatewaySnapshot` to a core name.

## Done today (2026-10-16)

- CI green for the first time since at least September. Three Linux SSH login bugs fixed: signal setup after rlimits, the NPROC/AS defaults, and bubbletea's terminal query.
- adsshadm with snoop, end to end, reviewed.
- Open core chosen (Apache core, BSL enterprise), wave 1 merged, CI checks both builds.
