#!/usr/bin/env bash
# Render packaging/homebrew/adssh.rb.template.
# Refuses unless VERSION is free of shell-breaking characters and every
# SHA-256 is 64 hex characters. This does not publish a tap and does not
# invent checksums. A formula with empty placeholders is not installable.
set -euo pipefail

usage() {
  echo "usage: render-homebrew-formula.sh VERSION DARWIN_ARM64_SHA256 DARWIN_AMD64_SHA256 LINUX_ARM64_SHA256 LINUX_AMD64_SHA256 [OUT]" >&2
  exit 2
}

if [[ $# -lt 5 || $# -gt 6 ]]; then
  usage
fi

VERSION="$1"
SHA_DARWIN_ARM64="$2"
SHA_DARWIN_AMD64="$3"
SHA_LINUX_ARM64="$4"
SHA_LINUX_AMD64="$5"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${6:-$ROOT/packaging/homebrew-tap/Formula/adssh.rb}"

if [[ -z "$VERSION" ]]; then
  echo "render-homebrew-formula: version is empty" >&2
  exit 2
fi
if printf '%s' "$VERSION" | grep -q '[[:space:]/\\|&]'; then
  echo "render-homebrew-formula: version contains a forbidden character" >&2
  exit 2
fi

hex='^[0-9a-fA-F]{64}$'
for sha in "$SHA_DARWIN_ARM64" "$SHA_DARWIN_AMD64" "$SHA_LINUX_ARM64" "$SHA_LINUX_AMD64"; do
  if [[ ! "$sha" =~ $hex ]]; then
    echo "render-homebrew-formula: SHA-256 must be 64 hex characters" >&2
    exit 2
  fi
done

template="$ROOT/packaging/homebrew/adssh.rb.template"
if [[ ! -f "$template" ]]; then
  echo "render-homebrew-formula: template missing" >&2
  exit 2
fi

mkdir -p "$(dirname "$OUT")"
sed \
  -e "s|{{VERSION}}|${VERSION}|g" \
  -e "s|{{DARWIN_ARM64_SHA256}}|${SHA_DARWIN_ARM64}|g" \
  -e "s|{{DARWIN_AMD64_SHA256}}|${SHA_DARWIN_AMD64}|g" \
  -e "s|{{LINUX_ARM64_SHA256}}|${SHA_LINUX_ARM64}|g" \
  -e "s|{{LINUX_AMD64_SHA256}}|${SHA_LINUX_AMD64}|g" \
  "$template" >"$OUT"

if grep -q '{{' "$OUT"; then
  rm -f "$OUT"
  echo "render-homebrew-formula: template placeholder remained" >&2
  exit 2
fi
