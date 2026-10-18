# systemapi.io break-glass uses adssh out of process

The systemapi agent does not import `github.com/afterdarksys/adssh/engine`.
The engine module pulls the cloud SDK graph. Break-glass stays a child process.

## What the agent does

`systemapi-agent/pty.go` `breakglassCommand` calls `exec.LookPath("adssh")`.
A missing binary returns `adssh_missing`. The agent does not fall open to bash.
The child is started with no `-r` flag. Authorization is the control-plane lease
that was checked before the PTY started, plus the scope `breakglass:open`.

The agent writes `breakglass.rego` mode `0600` under the state directory:

```rego
package adssh.authz

default allow = true
```

That policy is allow-by-default on purpose. It exists so the HMAC audit chain
records the session. The lease and the API scope are the authorization. The
child environment sets `ADSSH_POLICY` to that file and `ADSSH_AUDIT_LOG` under
the same state directory. Child environment names that start with `SYSTEMAPI`,
contain `API_KEY`, or start with `ADSTELCO` are stripped before both the login
shell and adssh.

The child can be the core build (`go build`). `adssh sah` (sah/1) and
`identity device login` exist only in the enterprise build (`go build -tags ee`);
see [EMBEDDING.md §7](EMBEDDING.md#7-core-and-enterprise-builds).

A second `pty_start` replaces the active session. Follow-up `pty_input`,
resize, and stop frames are not re-leased. The kill timer is `expiresUnix`.

## In-process hosts

A host that can take the engine dependency should follow
[EMBEDDING.md](EMBEDDING.md). Construction is fail-closed: a bad policy returns
no engine. `RunShell` runs `GateProgram` before `Runner.Run`, so a declaration
such as `export` cannot skip the gate. `RunStarlark` executes on the session
thread. `print` is not a policy decision. `sys.exec_cmd` stays on the session
engine's gate.

Zero `engine.Config` is allow-by-default with no audit chain. Production hosts
set `RequirePolicy` and a chain key.
