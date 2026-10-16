# Licensing

adssh is open core.

**The core is open source under the Apache License 2.0** (`LICENSE`). The core is the shell, the SSH server and client, the policy engine, the audit log and hash chain, the virtual binaries, the Starlark standard library, the MCP server, and the attach protocol. Anyone may use, modify, ship, and sell it, including Linux distributions and appliance vendors. The goal is for adssh to be available everywhere SSH is.

**The enterprise layer is source-available under the Business Source License 1.1** (`ee/LICENSE`). This is everything under `ee/` and every file whose name ends in `_ee.go` or `_ee_test.go`: the governance features an organization needs to run adssh at scale. Those files compile only into the enterprise build (`go build -tags ee`). A plain `go build` produces the Apache-licensed core, and CI fails if the core build ever includes an enterprise file.

| You are | Core | Enterprise layer |
|---|---|---|
| Anyone, for development, testing, or evaluation | free | free |
| An individual or organization under US$1M annual revenue, in production | free | free |
| An organization at or over US$1M annual revenue, in production | free | commercial license |
| Offering adssh's enterprise features as a hosted or managed service | free (core) | commercial license |

Each enterprise release becomes Apache 2.0 four years after it is published.

Commercial licenses: https://billing.afterdarksys.com

## Trademarks

"adssh" and "sah" are trademarks of After Dark Systems. The Apache license covers the code, not the names. A fork may use the code but must not call itself adssh or sah.

## Contributions

Contributions to the core are accepted under Apache 2.0. Contributions to `ee/` or to any `_ee.go` file require a contributor agreement, because After Dark Systems sells commercial licenses for that code.
