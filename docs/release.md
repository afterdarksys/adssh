# Cutting an adssh release

This is the cut procedure. Running it is a human decision in the morning. This file does not tag, push, sign, or publish.

## What is in the repository

- `.github/workflows/release.yml` builds on a `v*` tag and on `workflow_dispatch`.
- `scripts/package-release.sh` writes `dist/adssh_${VERSION}_${goos}_${goarch}.tar.gz` plus deb, rpm, `SHA256SUMS`, `provenance.json`, and `slsa-provenance.intoto.json`.
- `scripts/render-homebrew-formula.sh` fills `packaging/homebrew/adssh.rb.template`.
- `packaging/homebrew-tap/README.md` says that directory is not a published tap.

`VERSION` is the git tag, including a leading `v` when the tag has one. The four archives are `darwin/arm64`, `darwin/amd64`, `linux/arm64`, and `linux/amd64`.

`provenance.json` and `slsa-provenance.intoto.json` are metadata written by the packaging script. They are not a signed SLSA attestation. Do not commit either file.

## GPG

The workflow imports `secrets.GPG_PRIVATE_KEY` only when that secret is non-empty. `package-release.sh` then runs `gpg --batch --yes --armor --detach-sign SHA256SUMS` because `GPG_SIGN=1`. No private key belongs in git. If the secret is absent, the checksum file is still written and it is unsigned. A signature is real only after that Actions step runs with the key.

## Homebrew

After a release exists, copy the four archive digests from `SHA256SUMS` and render:

```sh
scripts/render-homebrew-formula.sh vX.Y.Z \
  "$DARWIN_ARM64_SHA256" "$DARWIN_AMD64_SHA256" \
  "$LINUX_ARM64_SHA256" "$LINUX_AMD64_SHA256"
```

Pass a sixth argument to write somewhere else, for example `/tmp/adssh.rb`. The default path is `packaging/homebrew-tap/Formula/adssh.rb`. The script exits 2 unless every digest matches `^[0-9a-fA-F]{64}$`. Creating the tap repository and pushing the formula are separate steps. This repository does not create that GitHub repository.

## SLSA

On a tag, the `provenance` job calls:

`slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0`

That generator's latest release is v2.1.0 (February 2025). The project is no longer actively maintained. The generic generator attests the SHA-256 subjects the caller supplies in `base64-subjects`. It does not rebuild the artifacts in a hermetic builder. The subjects are `sha256sum dist/*`, base64-encoded on one line, and only when `github.ref` is a tag and `dist` is non-empty. `upload-assets` is true. Job permissions are `actions: read`, `id-token: write`, and `contents: write`.

`workflow_dispatch` on a branch is not `refs/tags/`, so that run does not start the provenance job. Nothing is signed until a real Actions run on a tag. No attestation file is checked in.

## What this procedure does not do

It does not publish a Homebrew tap, import a key, forge a digest, or treat the 2026-10-12 security note as permission to tag.
