# adsshadm

`adsshadm` administers a running adssh through the local admin API that `adssh admin serve` starts. With no command it opens an `adsshadm>` prompt with completion. With a command it runs that command and exits.

```sh
adsshadm                                  # interactive prompt
adsshadm sessions                         # one command
adsshadm --json approvals                 # raw JSON
adsshadm --yes approve 7f3a               # no confirmation
```

## Connecting

- `--url` or `ADSSH_ADMIN_URL`: `unix:/path` (preferred), or a loopback `http://` address with a port. `http://127.0.0.1:8787` is the `admin serve` default. Any other host is refused, because the admin API only listens on loopback or a socket and the key would otherwise cross the network in clear text. A socket must be owned by you or root, and should sit in a directory only its owner can write, since the check and the connect are separate steps. A loopback port cannot be checked that way, so another local user who binds it while adssh is down could collect the key. Use a socket where that matters. For a remote adssh, run `adsshadm` on that host or forward its socket over SSH.
- `--key-file` or `ADSSH_ADMIN_KEY_FILE`: a file holding one key. It must be a regular file owned by you with mode 0600, not a symlink. The key is never taken from argv or an environment value.

The read-only key (`ADSSH_ADMIN_API_KEY`) can list, explain, and export evidence. `approve`, `deny`, `guard unban`, and `snoop` need a named key from `ADSSH_ADMIN_KEYS`. The key name is what the server records as the actor.

## Commands

| Command | What it does |
|---|---|
| `sessions` | live sessions |
| `gateways`, `recordings`, `elevations`, `leases` | the matching admin lists |
| `approvals` | pending four-eyes requests |
| `approve <id>`, `deny <id>` | decide a request (named key) |
| `explain <session-id> <command...>` | how policy would decide a command |
| `evidence [session-id] [--since T] [--until T] [--change ID]` | a verified evidence bundle |
| `guard`, `guard unban <addr>` | the SSH jail; unban needs a named key |
| `snoop <session-id> <user> [--rw] --purpose support\|investigation --reason TEXT` | attach to a live session |

Tab completes command names and live values: request ids, session ids and users, banned addresses. `approve`, `deny`, `unban`, and `snoop` ask first unless `--yes` is given. A non-interactive run without `--yes` refuses them. `approve` and `deny` look the request up first, show the requester, host, and command in the question, and refuse an id that is not pending.

Every string from the server was typed by some user, so control characters and bidi overrides in it are shown as escapes (`\x1b`, `\u202e`) rather than sent to the terminal. A pending command cannot redraw itself as something harmless.

## snoop

`snoop` attaches to another user's live terminal, view-only unless `--rw` is given. Ctrl-] detaches. Every attach carries a purpose (`support` or `investigation`) and a reason, and the server writes both onto the attach and detach audit records. The session must match both the id and the user.

The server decides the rest:

- Whether the watched user sees a notice. `ADSSH_SNOOP_NOTIFY_LOCK=on` forces the notice on and nothing can silence it, for jurisdictions that require notice. Otherwise a Rego rule may decide per purpose, user, or session. Otherwise `ADSSH_SNOOP_NOTIFY` (`on` or `off`, default `on`) applies. An investigation is shown to the watched user unless a Rego rule explicitly returns `notify=false`. The operator default alone cannot silence it.
- Whether the key may use `--rw`: a named key, the `admin.snoop.rw` entitlement granted to that key name explicitly (a `*` entitlement does not count), a session with a terminal, and four-eyes approval. For support, the session owner approves by default. For investigation, a second named admin key approves, never the owner. While approval is pending, `snoop` prints the request id for the approver to `adsshadm approve`. Run `snoop` again once it is approved.

The attach and detach audit records (`MIRROR_ATTACH`, `MIRROR_DETACH`) carry the key name, mode, purpose, reason, session, user, and whether the user was notified. They go into both the audit log and the hash chain.

Against an adssh older than the attach endpoint, `snoop` reports that the server has no attach endpoint.
