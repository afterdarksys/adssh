# Recordings and evidence

## Recordings

Session recordings are JSONL files. The directory is `ADSSH_RECORD_DIR` when that variable is set, otherwise `~/.adssh/recordings`.

List and evidence readers accept only regular files whose names end in `.jsonl`. Symlinks are skipped. The session id is the basename without the extension. Names that contain a path separator or `..` are rejected. A missing directory is an empty list, not an error.

`GET /v1/recordings` and MCP `admin_list_recordings` use that filter.

## Evidence bundle

`evidence` verifies the configured HMAC chain before it returns a bundle. Filtering does not skip verification. Every returned entry keeps its original chain hashes.

`digest_sha256` is the hex SHA-256 of `json.Marshal` of the selected chain entries. The digest is computed before lease views are attached. Recording references and the gateway log reference are also outside that digest. Each recording reference has its own `digest_sha256` of the recording file.

`GET /v1/evidence` is the same bundle on the local admin API. It is not a public evidence service.

## Elevations

`elevate` writes elevation request and drop lines to the HMAC chain. `GET /v1/elevations` and MCP `admin_list_elevations` parse those lines and add active in-memory grants from the current process. Only event lines count. A typed command that looks like an elevation line is ignored. The request line is written before the grant, so a failed audit write grants nothing. An active grant has a role, a reason, and an expiry. It does not store a separate TTL field.

An empty chain path returns `chain_unavailable` (HTTP 503). A configured path whose file does not exist returns an empty list and does not add active-only grants. A present, verified, empty file includes active in-memory grants. A failed chain verification is an error.

Quote-containing elevation reasons are a known limit of the line parser.

A policy denial of `elevate` can send the optional approval webhook. The notice does not grant the role.
