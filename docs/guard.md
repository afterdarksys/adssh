# SSH listener jail

`guard` counts failed SSH handshakes and connection rate on the adssh listener (`adssh --serve` and `sys.enable_ssh`). A banned peer is closed before the handshake. The listener accepts public keys and certificates. The ban is enforced inside that listener. nftables and pf are out of scope.

## Files

Config and the ban file live in the same directory `adssh --init` creates. That is `~/.adssh`, or `$XDG_CONFIG_HOME/adssh` when `XDG_CONFIG_HOME` is set.

| File | Environment variable | Default |
|---|---|---|
| `guard.yaml` | `ADSSH_GUARD_CONFIG` | `~/.adssh/guard.yaml` |
| `guard-state.json` | `ADSSH_GUARD_STATE` | `~/.adssh/guard-state.json` |

`ADSSH_GUARD` is the process switch. It is read as written:

- Unset follows `guard.yaml`. A missing file uses the defaults below and leaves the jail enabled.
- `1`, `true`, `yes`, or `on` forces the jail on. The switch wins over `enabled: false` in the file.
- `0`, `false`, `no`, or `off` forces the jail off. The process skips both files, so a corrupt file does not block startup.
- Any other value fails closed (`invalid ADSSH_GUARD value`).

`adssh --serve` exits 1 when the config or the ban file is invalid. A REPL or `-c` process prints `adssh: guard: ...` and keeps running. `adssh-mcp` prints `adssh-mcp: guard: ...` and keeps running. MCP has no unban tool.

`adssh --init` writes a commented `guard.yaml` at mode `0600` when that file is absent. `adssh --doctor` reports the switch, the config file, and the ban file. A missing config is a warning, because the defaults apply. A missing ban file is reported as `no ban file yet`. An invalid ban file is a failure even when `ADSSH_GUARD=off`.

## Defaults

A missing `guard.yaml`, or a file that is `{}`, uses:

| Key | Default |
|---|---|
| `enabled` | `true` |
| `find_time` | `10m` |
| `max_retry` | `5` |
| `ban_time` | `1h` |
| `rate_limit` | `30` |
| `rate_window` | `1m` |
| `max_entries` | `10000` |
| `ignore` | `127.0.0.0/8`, `::1/128` |

An omitted `ignore` key uses those two networks. That includes IPv4-mapped loopback (`::ffff:127.0.0.1`). An explicit empty list (`ignore: []`, `ignore:`, or `ignore: null`) ignores nothing, including loopback.

Ignore entries are CIDR only. A hostname is rejected. A prefix length of `/0` (`0.0.0.0/0`, `::/0`) is rejected. `/1` is accepted. `::ffff:1.2.3.4` and `1.2.3.4` share one bucket, and the stored address is the IPv4 form.

Limits: `max_retry` 1..100, `rate_limit` 1..10000, `max_entries` 1..100000, `ban_time` 1s..8760h, `find_time` 1s..24h, `rate_window` 1s..1h. Durations are Go duration strings such as `10m` and `1h`. Zero, negative, and non-duration values are rejected. Unknown YAML fields are rejected. An empty or comment-only file is rejected. The config must be a regular file of at most 64KiB, and it must not be a symlink or group/world writable.

`enabled: false`, with the switch unset, still validates the ban file. Admit then allows every peer and does not count. Unban still works, so the table can be cleared.

## What is counted

Each accepted TCP connection is checked before the SSH handshake.

- A peer inside an ignore network is allowed and is not counted. That stays true while the jail is tripped.
- An address that is not an IP or `host:port` is refused (`bad_peer`).
- An active ban is refused (`banned`). The connection is closed and does not add a strike.
- When the ban table already holds `max_entries` bans, a new address is refused (`table_full`).
- `rate_limit` connections from one address inside `rate_window` create a ban with reason `rate`. The connection that crosses the limit is the one refused.
- A failed handshake counts as one strike. That covers a rejected key and a garbage banner. `max_retry` strikes inside `find_time` create a ban with reason `handshake`.
- A successful handshake does not clear strikes.

A ban is active while `until` is strictly after the current time. After it expires, the next connection is allowed. Strikes older than `find_time` are dropped. A later failure can ban the address again. Expiry leaves strikes that are still inside `find_time` in place.

Strikes and the rate window live in memory. A restart clears them. Bans are the JSON file.

## Ban file

`guard-state.json` must be mode `0600`, a regular file, at most 1MiB, and `v` must be `1`.

```json
{"v":1,"bans":[{"addr":"203.0.113.10","until":"2026-10-15T13:00:00Z","reason":"handshake"}]}
```

Stored reasons are `handshake` and `rate`. The whole file is rejected for an unknown reason, a duplicate address, an unparseable address, a zero `until`, an `until` more than 366 days ahead, an unknown JSON field, trailing JSON, a symlink, or any mode other than `0600`.

The file is not signed. Mode `0600` and a rename inside the same directory are the integrity controls. A local user who can write the file can remove a ban. The file body and key material are not written to the audit log.

`{"v":1}` with `bans` omitted is an empty table. Expired bans are dropped when the file is loaded. A rewrite from a new ban or an unban also omits bans that have already expired.

## Commands

`guard` is a virtual binary. It passes the same policy gate as other shell commands.

```text
guard status
guard config
guard list
guard unban 203.0.113.10
guard reload
```

`--json` may appear anywhere after the command name. `status` prints the effective config and the active bans. `config` prints the config and omits the bans. `list` prints the bans. `reload` rereads `guard.yaml` and the ban file. `unban` removes one ban and that address's strikes. The address may be an IP or `host:port`. `::ffff:1.2.3.4` unbans the address stored as `1.2.3.4`.

## Local admin API

`admin serve` is the local admin API. It is not a public API. The routes require the same API key as the other `/v1` routes.

- `GET /v1/guard` returns the effective config and the active bans. The body is still returned when the jail is tripped.
- `POST /v1/guard/unban` takes `{"addr":"<ip or host:port>"}`. Success is `{"ok":true,"addr":"<canonical ip>"}`.

An empty body, an unknown field, trailing JSON, or an address that is not an IP is HTTP 400. An address that is not banned is HTTP 404 `{"error":"not_banned"}`. A ban file that cannot be updated is HTTP 500 `{"error":"guard_unavailable"}`. A jail that is forced off, or that has never been configured, is HTTP 500 `{"error":"guard is not active"}`. The error body is a short token. It does not include the file path.

The schema is `docs/openapi/admin.yaml`.

## Two processes

The SSH daemon and a console command such as `adssh -c 'guard unban 203.0.113.10'` are different processes. The ban file is the shared table. Before admit, a failed handshake, list, unban, and status, the daemon reloads the file when its size or modification time changes. An unban from the file also clears that address's in-memory strikes, so the next failure starts again from zero.

A second `admin serve` process reads and writes the same file. A `guard` command in the daemon's own process updates memory and the file together.

## Audit

The audit log records a ban, an unban, a reload, and the failure that crossed a threshold:

```text
GUARD action=threshold addr=203.0.113.10 reason=handshake
GUARD action=ban addr=203.0.113.10 reason=handshake
GUARD action=unban addr=203.0.113.10 reason=operator
GUARD action=reload addr= reason=config
```

Actions are `ban`, `unban`, `reload`, and `threshold`. Reasons are `handshake`, `rate`, `operator`, and `config`. A refused connection that does not cross a threshold is not appended to the chain.

## When a write fails

A failed write of the ban file keeps the new ban in memory, records the threshold and the ban, and then refuses every non-ignored peer with reason `guard_unavailable`. Loopback stays allowed when it is still in the ignore list. The jail stays in that state until `guard reload` or a process restart. Admit does not clear the trip on its own.

`guard reload` trusts the files on disk. A ban that never reached disk is absent after a reload that reads a file without that ban. The audit event from the failed write remains. Reload of a bad config keeps the previous good config and does not trip. Reload of a bad ban file trips the jail and keeps the new config.

A ban file that disappears after the jail has seen it trips the jail. A file that has never existed is an empty table.

`adssh --serve` and `sys.enable_ssh` call the jail ready check after the root check and before they write a host key. A tripped jail returns an error from that check.
