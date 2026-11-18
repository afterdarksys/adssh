#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
gitleaks dir --redact --no-banner internal/userland
gitleaks dir --redact --no-banner cmd/adssh-userland
gitleaks dir --redact --no-banner tools/userland
gitleaks dir --redact --no-banner security/vbin_userland.go
go vet ./internal/userland/... ./cmd/adssh-userland ./security
govulncheck ./internal/userland/... ./cmd/adssh-userland
cd tools/userland
go vet ./...
govulncheck ./...
