# SAH suite — adssh

Status: 2026-10-12. The suite contract is `~/development/systemapi.io/docs/sah-suite.md` when the repositories are sibling checkouts. This file is the local contract.

adssh is the execution shell. The brand word is sah (Service Automation Hub). The hub encompasses the platform and the suite of utilities. This repository is not renamed. The binary stays `adssh`, the MCP binary stays `adssh-mcp`, the module stays `github.com/afterdarksys/adssh`, config stays `~/.adssh`, and the GitHub repo stays `afterdarksys/adssh`.

`admin serve` is the local admin HTTP API. It is not a second public API.

`identity oidc import` verifies an already-issued OIDC JWT. It does not accept the opaque device-login bearer. `identity device login` is a client of the systemapi control plane at `controlplane/oauth.js`. It stores that bearer in a 0600 file and sets the session user with no groups. An Authentik access token is not that bearer. The authorization server stays in systemapi.

The systemapi agent does not import this module. Break-glass is a child process. See `docs/systemapi-embed.md`.

The design handoff (computeapi provisions, the machine enrolls through systemapi, adssh executes under a lease) is not wired. Do not mark it implemented from this note.

`ADSSH_SAH` defaults off. `1`, `true`, or `yes` turns on `adssh sah`, which speaks one `sah/1` stdio frame. The response `handoff` stays `not_wired`. `sahconnect ssh` does not set the switch. `execute` fails closed with `policy_required` when no policy is loaded. A frame `lease_id` does not authorize the command.

## Next

`make test` in this repository. Suite index: `opensah tools` in `~/development/opensah`.
