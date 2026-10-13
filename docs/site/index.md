# adssh documentation source

These pages are the source for a docs site. They are not hosted. Publishing them is a separate morning step.

adssh is the execution shell in the SAH suite. SAH means Service Automation Hum. The development name stays `adssh`. The binary stays `adssh`, the MCP binary stays `adssh-mcp`, the module stays `github.com/afterdarksys/adssh`, config stays `~/.adssh`, and the GitHub repository stays `afterdarksys/adssh`.

The suite contract is `docs/sah-suite.md` in this repository and `docs/sah-suite.md` in systemapi. If a brochure README and that contract disagree, the contract wins.

## Pages

- [Install and packaging](install.md)
- [Architecture](architecture.md)
- [Policy authoring](policy.md)
- [Gateway](gateway.md)
- [Leases](leases.md)
- [Recordings and evidence](recordings.md)
- [MCP and agent governance](mcp.md)

In-process embedding is `docs/EMBEDDING.md`. The systemapi out-of-process break-glass path is `docs/systemapi-embed.md`. The release cut procedure is `docs/release.md`.

## What is true today

`ADSSH_SAH` defaults off. `1`, `true`, or `yes` turns on `adssh sah`, which reads one `sah/1` JSON frame from stdin and writes one JSON response. The response field `handoff` is `not_wired`. A frame `lease_id` does not authorize the command. `execute` returns `policy_required` when no policy is loaded.

The design sentence "computeapi provisions, the machine enrolls through systemapi, adssh executes under policy and a lease" is not an implementation. Wired compute adapters are Vast.ai and io.net.

`identity device login` is a client of the systemapi control plane. It stores an opaque bearer. It does not import OIDC groups. The authorization server stays in systemapi.

`admin serve` is the local admin HTTP API. It is not a second public API. The default listen address is `127.0.0.1:8787`. `--listen` can bind a wider address.

The Homebrew tap is not published. The SLSA workflow has not produced a signed attestation. `package-release.sh` writes `provenance.json` and `slsa-provenance.intoto.json` as local metadata. Those files are not a signed attestation.
