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

## Provenance

On a tag, after `Package`, the release job runs `actions/attest-build-provenance@v4` with `subject-path: 'dist/*'`. GitHub signs a Sigstore-backed build-provenance attestation for every file in `dist/` and stores it with the repository. The job has `id-token: write` and `attestations: write` for that step. Verify a downloaded asset with:

```sh
gh attestation verify adssh_vX.Y.Z_darwin_amd64.tar.gz --repo afterdarksys/adssh
```

`workflow_dispatch` on a branch is not `refs/tags/`, so a dispatch run packages and uploads artifacts but does not attest or publish. No attestation file is checked in. The earlier `slsa-github-generator` job is gone; that project's last release is v2.1.0 (February 2025) and it is no longer maintained.

## Homebrew tap

`afterdarksys/homebrew-tap` exists and publishes formulas through its `scripts/publish-spec.sh --spec <repo>/homebrew-formula.json` (kind `go` builds from the tag archive). adssh does not ship there yet: it needs a `homebrew-formula.json` at the repo root and a LICENSE file (the formula has a `license` field and the repository is public with none). The `render-homebrew-formula.sh` path above is the older, manual route and becomes redundant once the spec file exists.

## What this procedure does not do

It does not publish a Homebrew tap, import a key, forge a digest, or treat the 2026-10-12 security note as permission to tag.
