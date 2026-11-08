# Per-user internal access

The enterprise build provides a public SSH gateway whose users have different
administrator-managed destination lists. The gateway must have network routes
to those destinations. Nothing needs to listen publicly on the internal hosts.

```text
ssh alice@sshgw.adsas.id
adssh> proxy list
adssh> proxy app.internal 22
```

`proxy host port` opens an interactive SSH shell, returns to adssh when that
shell exits, and forwards terminal size changes. `proxy list` emits JSON for
only the current user's destinations. Lists are access grants; users must not
be able to edit them.

## Configuration

Build with `go build -tags ee`. Set `ADSSH_PROXY_CONFIG` in the **listener's**
environment to an absolute path such as `/etc/adssh/proxy.json`. Keep the file
and its parent directories administrator-controlled. The reader rejects final
symlinks, nonregular files, group/world-writable files, wrong ownership, unknown
fields, malformed entries, and files larger than 1 MiB. A missing configured
file denies new proxy and native forwarding requests.

Example (replace the host-key placeholder with the real host's Ed25519 public
key, obtained through a trusted administrative channel):

```json
{
  "users": {
    "alice": [
      {
        "host": "app.internal",
        "ip": "10.20.0.10",
        "port": 22,
        "user": "alice",
        "host_key": "ssh-ed25519 REPLACE_WITH_REAL_PUBLIC_HOST_KEY"
      }
    ],
    "bob": [
      {"host": "db.internal", "ip": "10.20.0.20", "port": 5432}
    ]
  }
}
```

The `host` and port must match exactly. `ip` is a pinned literal destination
address; `proxy` dials it without a DNS lookup. No wildcards, arbitrary port
ranges, or implicit grants to other users are supported. Empty/missing user
lists grant nothing. SSH entries need `user` and `host_key`; TCP-only entries
omit both. The file is read for new authorization requests. Updates do not
terminate existing connections.

For interactive SSH, place the user's own **unencrypted Ed25519 private key**
at `~/.ssh/id_ed25519` in that user's gateway account, with mode `0600`, and
authorize its public key on the internal account. The client refuses unknown
or changed host keys. It does not use the listener's credentials, passwords,
agent forwarding, arbitrary identity paths, or a user's SSH config. This first
version does not support encrypted private keys. Native forwarding below lets
users retain their keys on their own computers instead.

Use `policy/examples/proxy-only.rego`, `--restricted`, and configured audit
logging for gateway-only users. The same destination allowlist also applies to
`gateway start` and native SSH `direct-tcpip`, so these cannot circumvent it.
The core build reserves `proxy` and refuses it as enterprise-only.

## TCP clients and client-held SSH keys

Use native forwarding from the user's own computer for binary protocols:

```sh
# Bob's local database client connects to localhost:15432.
ssh -N -L 127.0.0.1:15432:db.internal:5432 bob@sshgw.adsas.id

# Alice authenticates to the internal SSH host from her own computer.
ssh -J alice@sshgw.adsas.id alice@app.internal
```

For native forwarding, the gateway resolves the requested host once, requires
that IP to match the configured `ip`, and dials that checked IP. Therefore the
name must resolve correctly on the gateway. SSH keys/certificates must also
permit port forwarding. The target still authenticates the user's application
or SSH client; gateway authorization is not target authentication.

`proxy tcp host port` relays redirected stdin/stdout as a raw TCP byte stream:

```sh
printf 'request\n' | proxy tcp text-service.internal 9000
```

It refuses terminal input because a PTY can corrupt binary data. It does not
open a public port or create a listener on the user's laptop. Use native `-L`
for databases and other local applications. TCP payloads are not recorded or
interpreted; end-to-end TLS/SSH remains the application's responsibility.

## Authorization and boundaries

The listener checks the monitor-bound user, destination, port, pinned IP, Rego
policy, entitlements, and audit writes before the child receives the target.
Renamed interactive identities are refused; reconnect using the authorized
account. The child performs the actual connection under that Unix account.
Authorization records identify the destination; `PROXY_RESULT` records the
child-reported completed/failed outcome without credentials or terminal bytes.
These are not an independent network packet or remote-command audit.

This is an application-level access gate, **not an OS network sandbox**. An
unrestricted local shell, arbitrary Starlark network execution, a native exploit,
or a privileged operator can bypass child-side gates. A public gateway for
untrusted users needs restricted commands and OS/network confinement appropriate
to its threat model. The allowlist alone must not be advertised as containing
arbitrary code execution. Existing SSH listener connection/session caps still
apply; this feature makes no new capacity claim.

Across multiple gateways behind one hostname, deploy the same policy and
destination configuration, account mappings, target trust, and user credentials
on each host. Audit files remain local to each gateway.
