# SAH suite — adssh

Status: 2026-10-12. The suite contract is `~/development/systemapi.io/docs/sah-suite.md` when the repositories are sibling checkouts. This file is the local contract.

adssh is the execution shell. The brand word is sah (Service Automation Hum). This repository is not renamed. The binary stays `adssh`, the MCP binary stays `adssh-mcp`, the module stays `github.com/afterdarksys/adssh`, config stays `~/.adssh`, and the GitHub repo stays `afterdarksys/adssh`.

`admin serve` is the local admin HTTP API. It is not a second public API.

`identity oidc import` verifies an already-issued OIDC JWT. It is not the systemapi device login. Device login stays in systemapi `controlplane/oauth.js`. An Ed25519 device-login JWT is not what this importer verifies today.

The systemapi agent does not import this module. Break-glass is a child process. See `docs/systemapi-embed.md`.

The design handoff (computeapi provisions, the machine enrolls through systemapi, adssh executes under a lease) is not wired. Do not mark it implemented from this note.

## Next

`make test` in this repository. Suite index: `opensah tools` in `~/development/opensah`.
