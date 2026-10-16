# Gateway

`gateway` is a policy-audited local TCP forwarder. It is not a fleet bastion product and it does not enroll a machine.

```text
gateway start --listen 127.0.0.1:0 --target host:port [--name label]
gateway list
gateway stop <id>
```

`gateway start` defaults `--listen` to `127.0.0.1:0`. The kernel picks the port. Policy still has to allow the command before the listener opens.

Native SSH `direct-tcpip` on `adssh --serve` uses the same gateway authorization when policy allows it. The policy input is `input.gateway`.

For `direct-tcpip` and for `gateway start`, adssh resolves the requested name once and makes one policy decision with both values:

| Field | Value |
|---|---|
| `input.gateway.target_host` | The name the client asked for, for example `db.internal`. |
| `input.gateway.target_ip` | The address that name resolved to, for example `10.20.0.7`. |
| `input.gateway.target_port` | The port, as a string. |

adssh then dials `target_ip`, not the name. A `gateway start` keeps that address for its lifetime. A DNS answer that changes after the decision is never used. A policy that only checks `target_host` keeps working. A policy can also check `target_ip`, for example to refuse the instance metadata address or a subnet whatever name resolves to it, or allow a subnet by address alone. A name that does not resolve is refused. When the client asks for an address, `target_host` and `target_ip` are the same address. See `policy/examples/gateway_target_ip.rego`.

At most 16 `direct-tcpip` channels can be open at once on one SSH connection. The resolve and the dial each time out after 10 seconds.

Each accepted connection can be recorded with byte counts. `evidence` attaches a gateway log reference when that log exists. The evidence digest is the SHA-256 of the chain entries. It does not cover the gateway log reference. See [Recordings and evidence](recordings.md).

A policy denial of the `gateway` command can send the optional approval webhook (`ADSSH_4EYES_WEBHOOK`). The notice does not authorize the listener. Other commands are not notified on a plain policy denial.

`GET /v1/gateways` on `admin serve` lists gateways owned by that process. MCP does not add a separate gateway-start tool. An agent that needs a gateway goes through `run_shell` or the shell, and both still pass policy.
