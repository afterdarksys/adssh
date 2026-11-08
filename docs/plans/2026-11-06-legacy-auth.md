# Legacy auth support — adssh as the login process

Status: 2026-11-06. Decision note for an afternoon revisit. This is a reading of the tree, not a change, and not permission to add an authenticator.

adssh `--serve` is the replacement for sshd. The listener has one door. Unix accounts name the session after that door opens. Passwords, LDAP binds, and Kerberos are not on that door, and they should stay off it.

## What opens a session

`adssh --serve` accepts a public key or an SSH user certificate. `internal/sys/ssh.go` builds `ssh.ServerConfig` with `PublicKeyCallback` and `AuthLogCallback` only (`EnableSSH`, around the `ServerConfig` literal). There is no password callback, no keyboard-interactive, no PAM, and no GSSAPI.

A raw key in `~/.adssh/authorized_keys` (`ADSSH_AUTHORIZED_KEYS`) works only for the names on its `user="alice"` or `user="alice,bob"` option. `loadAuthorizedKeys` refuses a line without `user=`. A certificate works only for a name in its `ValidPrincipals`. An empty principal list is refused. `x/crypto/ssh` would treat an empty list as valid for every login; adssh does not. The CA is a `cert-authority` line in that same file. `user=` on a cert-authority line is refused, because a certificate is bound by its principals.

`identity ssh-ca issue` (enterprise build, `security/vbin_identity_ee.go`) mints those short-lived user certs. The cert is an SSH user cert, `permit-pty` only, principals taken from `--principal`, validity `now-1m` through `now+TTL`, signed by the CA key the operator passes. Issuance is audited as `IDENTITY_SSH_CERT_ISSUE`.

After the key check:

- `loginIsRoot` (`internal/sys/ssh.go`) refuses `root` and any name that resolves to uid 0 unless `SSHServerOptions.PermitRoot` is set (`ADSSH_SSH_PERMIT_ROOT`). A lookup failure at that check refuses the login.
- `RequireResolvableSSHUser` (`internal/sys/session_limits.go`) fails closed when the login name is empty or `user.Lookup` fails, before session goroutines start.
- `applyCredential` resolves uid, gid, and supplementary groups and sets `SysProcAttr.Credential` on the session child. A lookup, parse, or `GroupIds` error leaves `Credential` unset and the caller must not start the process. The listener stays root. The child is the dropped uid.

`lookupUser` is `os/user.Lookup` (`getpwnam` through the host NSS). The listener does not open `/etc/passwd` or `/etc/shadow` itself.

A local `adssh` with no `--serve` does not authenticate. It runs as the Unix user who started it. That path is the console. The login-process replacement is the listener.

## 1. passwd and shadow

The passwd database is already required, and only as the account record. `user.Lookup` asks the C library, so on a host whose `nsswitch.conf` points `passwd` and `group` at `sss` or `ldap`, an AD-backed account resolves the same way a local account does. That lookup is what makes the setuid drop safe. If it fails, the login stops.

Shadow should not become a fallback. The listener is root, so it could read the hash file, and a password check next to the key check is a second door that opens when the first one does not. Password spraying, lockouts, and a PAM stack that fails open are the surface removed with sshd. Keep NSS lookup. Leave the hashes unread.

Decision for the revisit: NSS name-to-uid stays mandatory and fail-closed. `/etc/shadow` is not an authenticator and is not a fallback.

## 2. AD, LDAP, and Kerberos

None of those are implemented, and none of them are a flag that is off. A search of the tree finds no `PasswordCallback`, no LDAP bind, no Kerberos ticket check, and no GSSAPI. `docs/plans/2026-07-18-cyberark-gap-analysis.md` lists directory and SSO integration as a PAM-buyer gap and says adssh is pubkey-only. That note is strategy, not scheduled work. It does not authorize an LDAP or Kerberos module.

Directory users still work when the operating system already projects them into NSS. sssd (or the equivalent) makes `alice` a uid. adssh then treats `alice` like any other login name: the certificate principal must be `alice`, and the lookup must succeed. The directory password never reaches adssh.

A switch labeled "legacy LDAP, default off" would still be live code in the root listener. Leave it unbuilt. If a host has no Unix account for that person, they do not get a session.

Decision for the revisit: do not add AD, LDAP, or Kerberos, including as a disabled option. Account projection stays in the OS (sssd / NSS). Authentication stays the key or the user cert.

## 3. OAuth, OIDC, and the SAH lease

OAuth is the way to prove the person and to mint the certificate. It is not a second handshake on the listener.

| Step | What it does | Where |
|---|---|---|
| `identity device login` | OAuth2 device code (`urn:ietf:params:oauth:grant-type:device_code`) against systemapi `controlplane/oauth.js`. Stores an opaque bearer in a mode `0600` file and sets the session user. Attaches no groups. | `security/device_login_ee.go`. Origin pinned by `ADSSH_CONTROLPLANE_URL`. Enterprise build. |
| `identity oidc import` | Verifies an already-issued OIDC JWT with the pinned issuer, JWKS URL, and audience. Attaches groups for Rego. An admin-audience import is what `elevate` requires before `os-root`, `adssh-admin`, or `gridops`. | `ADSSH_OIDC_*` and `ADSSH_OIDC_ADMIN_*`. Issuer, JWKS, and audience come from the environment only. Enterprise build. |
| SAH exec lease | Authorizes one command on an enrolled host. It does not log anyone in. A verified lease is necessary, not sufficient, and a `lease_id` on a frame does not authorize a command. | `security/execlease_ee.go`. `ADSSH_SAH_REQUIRE_LEASE` stays off. The provision → enroll → execute handoff is not wired (`docs/sah-suite.md`, `internal/sah/sah_ee.go`). |

Rules that stay in force:

- The device-login bearer must not be handed to `identity oidc import`. The importer checks an OIDC JWT via JWKS. The bearer is opaque.
- An Authentik access token is not that bearer. Dashboard login stays Authentik at `auth.afterdarksys.com`. The authorization server stays in systemapi.
- A session renamed by `identity device login` cannot approve or deny a four-eyes decision. A verified OIDC import can, once it marks the session `oidc-verified`.
- Login-audience imports strip `os-root`, `adssh-admin`, and `gridops`. Those names are policy group claims, not a uid change.
- Command allow and deny is Rego plus entitlements (user, groups, command), not OAuth scopes.
- `admin serve` is the local admin API. It is not a public login endpoint.
- Do not import this module into the systemapi agent. Break-glass stays a child process (`docs/systemapi-embed.md`).

## Replacement order

This is the order that replaces sshd. Revisit against this list.

1. The person proves themselves with device login or a pinned OIDC token.
2. That proof is what allows `identity ssh-ca issue` to mint a short-lived user certificate whose principal is the Unix login name.
3. The listener trusts that CA. The raw `user=` keys are a small bootstrap set.
4. NSS resolves the principal. A missing user fails closed. Root stays off.
5. Inside the session, `identity oidc import` supplies groups for policy.
6. Once the suite handoff is wired, the SAH lease is a second check on the command, still not a way through the door. Shipping that handoff requires a test and an edit to the Wired join list in the suite contract. This note does not do that.

## Open until the revisit

- Who is allowed to call `identity ssh-ca issue`, and which proof (device-login session versus `oidc-verified`) must already be on the session before a cert is minted. Today the vbin signs whatever CA key and principal the caller passes, and the audit line records the issuance. The listener then trusts any cert that chains to a `cert-authority` line.
- Whether bootstrap `user=` keys stay in `~/.adssh/authorized_keys` forever or expire once every operator has a cert.
- Confirm no host in the fleet is expected to log in with a password, an LDAP bind, or a Kerberos ticket directly to adssh. Those users need a Unix account via NSS and a cert.

## Sources checked

- `internal/sys/ssh.go` — pubkey and cert callback, `user=` binding, root refusal, no password callback.
- `internal/sys/session_limits.go` — `user.Lookup`, fail-closed credential drop.
- `security/device_login_ee.go` — device-code client.
- `security/vbin_identity_ee.go` — OIDC import and `identity ssh-ca issue`.
- `docs/sah-suite.md`, `AGENTS.md` — bearer versus JWT, handoff still not wired.
- `docs/plans/2026-07-18-cyberark-gap-analysis.md` — directory integration listed as a gap, not as built code.
