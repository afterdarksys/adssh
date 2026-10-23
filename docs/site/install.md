# Install and packaging

This page describes how a release is built. v0.10.0 (2026-10-19) is the first tagged release: `.github/workflows/release.yml` built it, GPG-signed `SHA256SUMS`, and attested build provenance on the tag push. The Homebrew tap publish is still pending.

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

Optional `GPG_SIGN=1` runs `gpg --batch --yes --armor --detach-sign SHA256SUMS`. The private key is a GitHub Actions secret named `GPG_PRIVATE_KEY`. It is not in git. If the secret is empty, `SHA256SUMS` is still written and it is unsigned. For v0.10.0 the secret was set: `SHA256SUMS.asc` is a real detached signature, key `310026CE56138229`, dated 2026-10-19.

The same script writes `provenance.json` and `slsa-provenance.intoto.json` next to the archives. Those files are local metadata. They are not a signed SLSA attestation themselves. Do not commit them. The real, cryptographically verifiable attestation is produced separately by the release workflow; see SLSA below.

## Homebrew

`packaging/homebrew/adssh.rb.template` is the formula template. `scripts/render-homebrew-formula.sh` fills `{{VERSION}}` and the four SHA-256 placeholders. It exits 2 when the version contains whitespace, `/`, `\`, `|`, or `&`, or when any digest is not 64 hex characters. It does not invent checksums.

`packaging/homebrew-tap/` in this repository is not a published tap. Do not point `brew tap` at it. The real tap is `afterdarksys/homebrew-tap` on GitHub, which publishes formulas via `scripts/publish-spec.sh --spec <repo>/homebrew-formula.json`. This repository carries that spec file and a `LICENSE` (added 2026-10-18). Rendering the spec against v0.10.0 produces a formula with the real tag-archive SHA-256, but that render has not been published: it sits uncommitted in a local tap checkout, and nothing under `Formula/` exists on the tap's remote yet.

The cut procedure is `docs/release.md`.

## SLSA

On a tag, `.github/workflows/release.yml` runs `actions/attest-build-provenance@v4` with `subject-path: 'dist/*'` after the `Package` step. GitHub signs a Sigstore-backed build-provenance attestation for every file in `dist/` and stores it with the repository; the job carries `id-token: write` and `attestations: write` for that step. `workflow_dispatch` on a branch is not `refs/tags/`, so a dispatch run packages and uploads artifacts but does not attest or publish.

v0.10.0 has one. Verify a downloaded asset with:

```sh
gh attestation verify adssh_v0.10.0_darwin_arm64.tar.gz --repo afterdarksys/adssh
```

The earlier sibling job that called `slsa-framework/slsa-github-generator` is gone; that generator's last release was v2.1.0 (February 2025) and the project is no longer maintained. No attestation file is checked in — it lives in GitHub's attestation store, not in git.

## sah/1

`ADSSH_SAH` defaults off. Unset, `on`, and any other value except `1`, `true`, or `yes` leave it off. When it is on:

```sh
ADSSH_SAH=1 adssh sah
```

The process reads one `sah/1` frame from stdin. `hello` does not execute a command. `execute` runs the command with `exec` and no shell, and only after a loaded policy allows it. No loaded policy returns `policy_required`. The response field `handoff` stays `not_wired`.
