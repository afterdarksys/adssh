# AGENTS.md

adssh is the execution shell. The brand is sah (Service Automation Hub). The hub encompasses the platform and the suite of utilities. This repo stays on the development name.

Architecture of the shell, MCP server, policy, and build commands is `CLAUDE.md`. Suite membership is `docs/sah-suite.md`. The cross-repo contract is `~/development/systemapi.io/docs/sah-suite.md`. If this file and `CLAUDE.md` disagree about the suite, this file wins. `CLAUDE.md` still wins for how the shell is built.

## Do this

1. Read `CLAUDE.md` before changing the shell, policy, SSH server, or `cmd/adssh-mcp`.
2. Read `docs/sah-suite.md` before adding a systemapi or computeapi client.
3. For crypto, tokens, TLS, SQL, randomness, or password hashing, follow `~/development/ads-fable-utils/SECURITY-RULES.md` before editing. Done when the change has a `Threats:` note and a negative test that rejects tampered, expired, oversized, or wrong-key input and fails closed.
4. Run `go test` on the packages you touched. Done when those packages report ok.

## Rules

- Keep the binary names `adssh` and `adssh-mcp`, the module `github.com/afterdarksys/adssh`, config `~/.adssh`, and the GitHub repo `afterdarksys/adssh`. A brand edit that renames them breaks the Go module path. GitHub would redirect the repo. The module path would not.
- Do not add an import of this module to the systemapi agent. Break-glass stays a child process (`docs/systemapi-embed.md`). The agent would otherwise pull the cloud SDKs.
- Keep `admin serve` as the local admin API. Describing it as a new public API advertises an interface that is not public.
- `identity oidc import` verifies an already-issued OIDC JWT via JWKS. Device login stays in systemapi `controlplane/oauth.js`. Do not point this importer at the device-login bearer.
- TLS verification stays on. `InsecureSkipVerify: true` accepts a forged peer.
- The provision → enroll → execute handoff is design. Ship it only with a test and an edit to the Wired join list in the suite contract.

## Next

`make test`
