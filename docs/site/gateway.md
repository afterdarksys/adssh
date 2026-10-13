# Gateway

`gateway` is a policy-audited local TCP forwarder. It is not a fleet bastion product and it does not enroll a machine.

```text
gateway start --listen 127.0.0.1:0 --target host:port [--name label]
gateway list
gateway stop <id>
```

`gateway start` defaults `--listen` to `127.0.0.1:0`. The kernel picks the port. Policy still has to allow the command before the listener opens.

Native SSH `direct-tcpip` on `adssh --serve` uses the same gateway authorization when policy allows it. The policy input is `input.gateway`.

Each accepted connection can be recorded with byte counts. `evidence` attaches a gateway log reference when that log exists. The evidence digest is the SHA-256 of the chain entries. It does not cover the gateway log reference. See [Recordings and evidence](recordings.md).

A policy denial of the `gateway` command can send the optional approval webhook (`ADSSH_4EYES_WEBHOOK`). The notice does not authorize the listener. Other commands are not notified on a plain policy denial.

`GET /v1/gateways` on `admin serve` lists gateways owned by that process. MCP does not add a separate gateway-start tool. An agent that needs a gateway goes through `run_shell` or the shell, and both still pass policy.
