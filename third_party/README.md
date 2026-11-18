# Userland third-party notices

adssh-userland uses [u-root](https://github.com/u-root/u-root), version v0.16.0,
commit a9c0bf61c74128eceaed057ee98f4068b603c5f9. Copyright belongs to the u-root
Authors. The BSD 3-Clause license is reproduced in `u-root/LICENSE`.

- `ls` and `cat` are compiled from the pinned dependency.
- `tools/userland/head/head.go` and `tools/userland/grep/grep.go` derive from
  `cmds/core/head/head.go` and `cmds/core/grep/grep.go`.
- `tools/userland/find/find.go` derives from `cmds/core/find/find.go`;
  `tools/userland/findcmd/find.go` derives from `pkg/core/find/find.go`.
- Local modifications propagate input/output and filesystem failures, reject
  invalid regex/glob patterns, preserve grep's no-match exit status, and fix
  head count handling. These files remain BSD licensed.

The multicall builder/runtime comes from
[gobusybox](https://github.com/u-root/gobusybox), `src` module v0.3.0.
Its BSD 3-Clause license is reproduced in `gobusybox/LICENSE`.

Ship these notices and license texts with distributions containing the worker.
Use of these projects does not imply endorsement by their authors.
The rest of adssh retains its existing licensing.
