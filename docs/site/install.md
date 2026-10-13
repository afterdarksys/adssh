# Install and packaging

This page describes how a release is built. It does not publish a tap, tag a release, or sign artifacts.

## Local binaries

From the repository root:

```sh
make build
make build-mcp
```

Those targets are `go build -o adssh .` and `go build -o adssh-mcp ./cmd/adssh-mcp`. `go.mod` requires Go 1.26.0.

## Release archives

`scripts/package-release.sh` builds four archives:

- `adssh_${VERSION}_darwin_arm64.tar.gz`
- `adssh_${VERSION}_darwin_amd64.tar.gz`
- `adssh_${VERSION}_linux_arm64.tar.gz`
- `adssh_${VERSION}_linux_amd64.tar.gz`

`VERSION` is the git tag, including a leading `v` when the tag has one. Each archive contains `bin/adssh`, `bin/adssh-mcp`, the man page, bash and zsh completions, and the policy share. The script also writes `SHA256SUMS`.

Optional `GPG_SIGN=1` runs `gpg --batch --yes --armor --detach-sign SHA256SUMS`. The private key is a GitHub Actions secret named `GPG_PRIVATE_KEY`. It is not in git. If the secret is empty, `SHA256SUMS` is still written and it is unsigned.

The same script writes `provenance.json` and `slsa-provenance.intoto.json` next to the archives. Those files are local metadata. They are not a signed SLSA attestation. Do not commit them.

## Homebrew

`packaging/homebrew/adssh.rb.template` is the formula template. `scripts/render-homebrew-formula.sh` fills `{{VERSION}}` and the four SHA-256 placeholders. It exits 2 when the version contains whitespace, `/`, `\`, `|`, or `&`, or when any digest is not 64 hex characters. It does not invent checksums.

`packaging/homebrew-tap/` is not a published tap. Do not point `brew tap` at it. Creating the tap repository and pushing a rendered formula are morning steps after a real `SHA256SUMS` exists. A formula with empty placeholders is not installable.

The cut procedure is `docs/release.md`.

## SLSA

On a tag, `.github/workflows/release.yml` can start a sibling `provenance` job:

`slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0`

That generator's latest release is v2.1.0 (February 2025). The project is no longer actively maintained. The generic generator attests the SHA-256 subjects the caller supplies. It does not rebuild the artifacts in a hermetic builder. The subjects are `sha256sum dist/*` for a non-empty `dist`, base64-encoded on one line, and only when `github.ref` is a tag. `workflow_dispatch` on a branch does not start that job. Nothing is signed until a real Actions run on a tag. No attestation is checked in.

## sah/1

`ADSSH_SAH` defaults off. Unset, `on`, and any other value except `1`, `true`, or `yes` leave it off. When it is on:

```sh
ADSSH_SAH=1 adssh sah
```

The process reads one `sah/1` frame from stdin. `hello` does not execute a command. `execute` runs the command with `exec` and no shell, and only after a loaded policy allows it. No loaded policy returns `policy_required`. The response field `handoff` stays `not_wired`.
