# Recordings and evidence

## Recordings

Session recordings are JSONL files. The directory is `ADSSH_RECORD_DIR` when that variable is set, otherwise `~/.adssh/recordings`.

List and evidence readers accept only regular files whose names end in `.jsonl`. Symlinks are skipped. The session id is the basename without the extension. Names that contain a path separator or `..` are rejected. A missing directory is an empty list, not an error.

`GET /v1/recordings` and MCP `admin_list_recordings` use that filter.

## Snoop

`adsshadm snoop <session-id> <user> [--rw] --purpose support|investigation --reason "..."` attaches through `GET /v1/sessions/{id}/attach` on the local admin API (see `docs/openapi/admin.yaml`). View needs a named admin key. rw also needs the `admin.snoop.rw` entitlement for the key name and a four-eyes approval: the session owner approves a support attach, a second named key approves an investigation. Every attach and detach is a `MIRROR_ATTACH`/`MIRROR_DETACH` chain event with key, mode, purpose, reason, session, user, and notify. Keystrokes are not audited; commands run during an rw attach carry `via=<key>`, and the recording captures the terminal as it does for `mirror console`. The owner sees `[adssh] <key> is viewing|controlling this session`. `ADSSH_SNOOP_NOTIFY=off` silences support attaches by default, policy may answer `notify` for command `snoop`, and `ADSSH_SNOOP_NOTIFY_LOCK=on` forces the notice over any policy.

## Evidence bundle

`evidence` verifies the configured HMAC chain before it returns a bundle. Filtering does not skip verification. Every returned entry keeps its original chain hashes.

`digest_sha256` is the hex SHA-256 of `json.Marshal` of the selected chain entries. The digest is computed before lease views are attached. Recording references and the gateway log reference are also outside that digest. Each recording reference has its own `digest_sha256` of the recording file.

`GET /v1/evidence` is the same bundle on the local admin API. It is not a public evidence service.

## Elevations

`elevate` writes elevation request and drop lines to the HMAC chain. `GET /v1/elevations` and MCP `admin_list_elevations` parse those lines and add active in-memory grants from the current process. Only event lines count. A typed command that looks like an elevation line is ignored. The request line is written before the grant, so a failed audit write grants nothing. An active grant has a role, a reason, and an expiry. It does not store a separate TTL field.

An empty chain path returns `chain_unavailable` (HTTP 503). A configured path whose file does not exist returns an empty list and does not add active-only grants. A present, verified, empty file includes active in-memory grants. A failed chain verification is an error.

Quote-containing elevation reasons are a known limit of the line parser.

A policy denial of `elevate` can send the optional approval webhook. The notice does not grant the role.
