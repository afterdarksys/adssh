#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT_SHA="${COMMIT_SHA:-$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)}"
DIST="${DIST:-$ROOT/dist}"
PLATFORMS="${PLATFORMS:-linux/amd64 linux/arm64 darwin/amd64 darwin/arm64}"
if [[ -x /usr/local/bin/go ]]; then
  GO_BIN="${GO_BIN:-/usr/local/bin/go}"
else
  GO_BIN="${GO_BIN:-go}"
fi

rm -rf "$DIST"
mkdir -p "$DIST"

build_platform() {
  local goos="$1"
  local goarch="$2"
  local name="adssh_${VERSION}_${goos}_${goarch}"
  local work="$DIST/$name"
  local bin_suffix=""
  if [[ "$goos" == "windows" ]]; then
    bin_suffix=".exe"
  fi

  mkdir -p "$work"/{bin,man,completions,packaging,policy}
  (
    cd "$ROOT"
    GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 "$GO_BIN" build -ldflags "-X main.version=$VERSION" -o "$work/bin/adssh$bin_suffix" .
    GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 "$GO_BIN" build -ldflags "-X main.version=$VERSION" -o "$work/bin/adssh-mcp$bin_suffix" ./cmd/adssh-mcp
  )
  cp "$ROOT/README.md" "$ROOT/CHANGELOG.md" "$ROOT/TODO.md" "$work/"
  cp "$ROOT/man/adssh.1" "$work/man/"
  cp "$ROOT/completions/adssh.bash" "$ROOT/completions/adssh.zsh" "$work/completions/"
  cp -R "$ROOT/packaging/homebrew" "$work/packaging/"
  cp -R "$ROOT/policy/default.rego" "$ROOT/policy/examples" "$ROOT/policy/bundles" "$work/policy/"

  tar -C "$DIST" -czf "$DIST/$name.tar.gz" "$name"
  rm -rf "$work"
}

for platform in $PLATFORMS; do
  IFS=/ read -r goos goarch <<<"$platform"
  build_platform "$goos" "$goarch"
done

(
  cd "$DIST"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum *.tar.gz > SHA256SUMS
  else
    shasum -a 256 *.tar.gz > SHA256SUMS
  fi
)

if command -v dpkg-deb >/dev/null 2>&1 && [[ -f "$DIST/adssh_${VERSION}_linux_amd64.tar.gz" ]]; then
  pkg="$DIST/adssh_${VERSION}_amd64"
  mkdir -p "$pkg/DEBIAN" "$pkg/usr/local/bin" "$pkg/usr/local/share/man/man1" "$pkg/usr/local/share/bash-completion/completions" "$pkg/usr/local/share/zsh/site-functions" "$pkg/usr/local/share/adssh/policy"
  cp "$DIST/adssh_${VERSION}_linux_amd64.tar.gz" "$pkg/" # retained as a source artifact inside staging during assembly
  tar -C "$pkg" -xzf "$pkg/adssh_${VERSION}_linux_amd64.tar.gz"
  cp "$pkg/adssh_${VERSION}_linux_amd64/bin/adssh" "$pkg/usr/local/bin/adssh"
  cp "$pkg/adssh_${VERSION}_linux_amd64/bin/adssh-mcp" "$pkg/usr/local/bin/adssh-mcp"
  cp "$ROOT/man/adssh.1" "$pkg/usr/local/share/man/man1/adssh.1"
  cp "$ROOT/completions/adssh.bash" "$pkg/usr/local/share/bash-completion/completions/adssh"
  cp "$ROOT/completions/adssh.zsh" "$pkg/usr/local/share/zsh/site-functions/_adssh"
  cp -R "$ROOT/policy/default.rego" "$ROOT/policy/examples" "$ROOT/policy/bundles" "$pkg/usr/local/share/adssh/policy/"
  rm -rf "$pkg/adssh_${VERSION}_linux_amd64" "$pkg/adssh_${VERSION}_linux_amd64.tar.gz"
  cat >"$pkg/DEBIAN/control" <<EOF
Package: adssh
Version: ${VERSION#v}
Section: admin
Priority: optional
Architecture: amd64
Maintainer: afterdarksys
Description: Security-first programmable DevOps shell and governed SSH gateway
EOF
  dpkg-deb --build "$pkg" "$DIST/adssh_${VERSION}_amd64.deb" >/dev/null
  rm -rf "$pkg"
fi

if command -v rpmbuild >/dev/null 2>&1 && [[ -f "$DIST/adssh_${VERSION}_linux_amd64.tar.gz" ]]; then
  rpmroot="$DIST/rpmbuild"
  mkdir -p "$rpmroot"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
  cp "$DIST/adssh_${VERSION}_linux_amd64.tar.gz" "$rpmroot/SOURCES/"
  cat >"$rpmroot/SPECS/adssh.spec" <<EOF
Name: adssh
Version: ${VERSION#v}
Release: 1
Summary: Security-first programmable DevOps shell and governed SSH gateway
License: Proprietary
BuildArch: x86_64

%description
adssh is a programmable DevOps shell with policy, audit, evidence, secret leases, and SSH gateway controls.

%prep
%setup -q -n adssh_${VERSION}_linux_amd64

%install
mkdir -p %{buildroot}/usr/local/bin
mkdir -p %{buildroot}/usr/local/share/man/man1
mkdir -p %{buildroot}/usr/local/share/adssh/policy
cp bin/adssh %{buildroot}/usr/local/bin/adssh
cp bin/adssh-mcp %{buildroot}/usr/local/bin/adssh-mcp
cp man/adssh.1 %{buildroot}/usr/local/share/man/man1/adssh.1
cp -R policy/* %{buildroot}/usr/local/share/adssh/policy/

%files
/usr/local/bin/adssh
/usr/local/bin/adssh-mcp
/usr/local/share/man/man1/adssh.1
/usr/local/share/adssh/policy
EOF
  rpmbuild --define "_topdir $rpmroot" -bb "$rpmroot/SPECS/adssh.spec" >/dev/null
  find "$rpmroot/RPMS" -type f -name '*.rpm' -exec cp {} "$DIST/" \;
  rm -rf "$rpmroot"
fi

(
  cd "$DIST"
  artifacts=( *.tar.gz )
  compgen -G "*.deb" >/dev/null && artifacts+=( *.deb )
  compgen -G "*.rpm" >/dev/null && artifacts+=( *.rpm )
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${artifacts[@]}" > SHA256SUMS
  else
    shasum -a 256 "${artifacts[@]}" > SHA256SUMS
  fi
  if [[ "${GPG_SIGN:-0}" == "1" ]]; then
    gpg --batch --yes --armor --detach-sign SHA256SUMS
  fi
)

python3 - "$DIST" "$VERSION" "$COMMIT_SHA" "$PLATFORMS" <<'PY'
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

dist, version, commit, platforms = sys.argv[1:5]
artifacts = []
for name in sorted(os.listdir(dist)):
    path = os.path.join(dist, name)
    if not os.path.isfile(path):
        continue
    if not (name.endswith(".tar.gz") or name.endswith(".deb") or name.endswith(".rpm")):
        continue
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            size += len(chunk)
            h.update(chunk)
    artifacts.append({"name": name, "size_bytes": size, "sha256": h.hexdigest()})

provenance = {
    "version": version,
    "commit_sha": commit,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "platforms": platforms.split(),
    "artifacts": artifacts,
    "checksum_file": "SHA256SUMS",
}
with open(os.path.join(dist, "provenance.json"), "w", encoding="utf-8") as f:
    json.dump(provenance, f, indent=2)
    f.write("\n")

attestation = {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [{"name": a["name"], "digest": {"sha256": a["sha256"]}} for a in artifacts],
    "predicateType": "https://slsa.dev/provenance/v1",
    "predicate": {
        "buildDefinition": {
            "buildType": "https://github.com/afterdarksys/adssh/actions/workflows/release.yml",
            "externalParameters": {"version": version, "platforms": platforms.split()},
        },
        "runDetails": {"metadata": {"invocationId": commit}},
    },
}
with open(os.path.join(dist, "slsa-provenance.intoto.json"), "w", encoding="utf-8") as f:
    json.dump(attestation, f, indent=2)
    f.write("\n")
PY

echo "release artifacts written to $DIST"
