#!/bin/sh
set -eu
cd "$(dirname "$0")/../tools/userland"
# Keep this module separate: command/build-tool dependencies do not enter adssh.
# go.sum pins both the source and the multicall generator.
go run -mod=readonly github.com/u-root/gobusybox/src/cmd/makebb \
  -o ../../adssh-userland-worker \
  github.com/u-root/u-root/cmds/core/ls \
  github.com/u-root/u-root/cmds/core/cat \
  ./head ./grep ./find
