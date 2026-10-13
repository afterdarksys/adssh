# Local Homebrew formula directory

This directory is not a published Homebrew tap. Do not point `brew tap` at it.

`Formula/adssh.rb` is produced by `scripts/render-homebrew-formula.sh` after a real release build. The script refuses to write a formula unless the version is free of `/`, `\`, `|`, `&`, and whitespace, and each of the four archive SHA-256 values is 64 hex characters. Empty placeholders are not an installable formula.

The checksums come from `SHA256SUMS` in a release produced by `scripts/package-release.sh`. This repository does not invent those digests and does not create the tap repository on GitHub.

See `docs/release.md` for the cut procedure.
