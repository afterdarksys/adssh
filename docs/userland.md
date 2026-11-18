# adssh-userland

The first userland milestone provides `cat`, `find`, `grep`, `head`, and `ls`
through a local gRPC daemon and a bundled u-root multicall worker. The shell,
MCP shell tool, and Starlark shell execution can invoke `userland exec` through
the existing virtual-command registry. It does not replace the host commands.

## Build and run

```sh
make build
make build-userland
mkdir -p ~/.adssh
./adssh-userland --policy "$PWD/policy/examples/userland.rego" \
  --audit "$HOME/.adssh/userland-audit.log"
```

Run as an ordinary user. The daemon refuses root. Create `~/.adssh` first if it
does not exist (`mkdir -p ~/.adssh`). The daemon creates its socket directory
with mode 0700; the socket defaults to `~/.adssh/userland/userland.sock`.
An existing socket or other file is never replaced. After an unclean shutdown,
confirm no daemon is running before removing a stale socket yourself.

In another terminal:

```sh
./adssh -c 'userland list'
./adssh -c 'userland exec ls -l'
./adssh -c "printf 'alpha\nbeta\n' | userland exec grep beta"
./adssh -c 'userland exec cat README.md | userland exec head -n 5'
./adssh -c 'userland exec find . -name "*.go" > files.txt'
```

For another socket use `userland --socket /absolute/private/directory/socket
exec ...`, paired with the daemon's `--socket`. Both processes must run as the
same Unix UID. The daemon's `--worker` defaults to `adssh-userland-worker` beside
the daemon binary; deploy both files together. The build uses a separate pinned
Go module in `tools/userland` and does not require the u-root tools on PATH.
The daemon currently imports the existing security package; separating a smaller
policy runtime from the rest of that package is future work.

## Execution and security contract

Threats: kernel peer-UID checks on both ends and a private socket directory reject
other local users and non-Unix transports. Required policy, audit, a fixed command
allowlist, stream limits, and execution deadlines protect the RPC execution path.
This is not protection against root or the owning UID. Workers have ordinary
access to everything that UID can read; neither a filesystem sandbox nor path
confinement is provided. Do not expose the socket to a less-trusted process under
the same UID and expect the shell's identity-specific policy to follow it.

- `userland exec` gates the wrapper and actual child argv on the shell engine.
  The daemon independently gates the child using its own required Rego policy,
  optional entitlements, existing approval hooks, and required audit log.
- Daemon identity is its OS user, authenticated through same-UID peer credentials;
  no caller-supplied identity, groups, preauthorization, or environment is accepted.
- One subprocess per invocation; explicit absolute cwd; minimal fixed environment.
  Shell aliases, variables, and directory changes stay in adssh. Paths are local
  to the daemon host, which is the same host in this milestone. Redirection stays
  with the shell. No automatic retries and no fallback to host execution.
- Bidirectional protobuf streaming preserves raw stdin/stdout/stderr bytes and
  carries an explicit process exit status. RPC failure is never command success.
- A disconnected or canceled RPC terminates its worker. Normal jobs cannot detach.
  Shutdown stops active RPCs. Workers are process-isolated, not containers.
- Limits: 30 seconds per invocation, 32 concurrent invocations, 256 argv entries,
  32 KiB total argv/cwd, 32 KiB stdin frames, 128 KiB gRPC messages, and 64 MiB each
  of stdin and combined stdout/stderr. Limit violations fail the invocation;
  callers may already have received partial output.
- Stdin supports files (including ordinary shell pipes) and in-memory readers.
  Unsupported custom reader types fail explicitly to avoid uninterruptible reads.
- Audit records include authorization and start/completion/abort events. They do
  not record stdout or stderr. This milestone does not provide durable job receipts.

The example policy permits all arguments to the five bundled commands. Customize
it for the deployment. Existing shell policy remains independent. `admin serve`
remains the local admin API; this service does not change suite enrollment or the
not-yet-wired provision/enroll/execute handoff.

## Command compatibility and upstream credit

These are u-root commands, not complete GNU coreutils replacements. Consult each
worker command's help and test your scripts before adopting it. `find` supports a
single root and a limited predicate set; it does not provide `-exec` or `-delete`.
The text scanners in `head` and `grep` reject overlong lines rather than silently
truncating them. Negative head counts are unsupported. Interactive PTYs, signal
forwarding other than cancellation, remote TLS, persistent jobs, and server-side
pipeline execution are outside this milestone.

The module toolchain is pinned to Go 1.27.4 to include the standard-library
security fixes found during integration. Transport dependencies use gRPC 1.83.2
and x/net 0.60.0. Run `scripts/check-userland-security.sh` before distribution.

Sources are pinned to u-root v0.16.0 and gobusybox/src v0.3.0. `ls` and `cat` use
upstream directly. The local BSD-derived `head`, `grep`, and `findcmd` adapters
retain copyright notices and fix error propagation, regex handling, no-match exit
status, and output/read errors. See `third_party/README.md`. Our code remains MIT;
the copied upstream code retains its BSD license.

## Verification

```sh
make test
make test-userland
# Additional concurrency check:
go test -race ./internal/userland/...
```

`make test-userland` builds the real worker, tests its adapters, then checks all
five commands through gRPC, shell pipelines, redirection, exit statuses, and
client policy denial. Ordinary tests cover direct-client daemon denial, audit
failure, malformed/oversized input, cancellation, socket permissions, environment
isolation, and output limits. The integration tests require Unix socket support.
Linux and macOS peer-credential implementations are provided.

The checked-in protocol is `internal/userland/pb/userland.proto`. Regenerate with
protoc and pinned `protoc-gen-go v1.36.11` / `protoc-gen-go-grpc v1.6.1`, using
`paths=source_relative` for both outputs.
