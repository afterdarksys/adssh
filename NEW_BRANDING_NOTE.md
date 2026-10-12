# Branding note

Date: 2026-10-12

`adssh` is the development name of the shell. The brand is **sah**, short for **Service Automation Hum**.

These directories exist under `~/development/`. Created 2026-10-12. On 2026-10-12 Ryan asked for the defined tools to be built. `opensah`, `sahlink`, `sahconnect`, and `sahapi` contain those tools. `sahcore` is still unassigned and is documentation only.

- `opensah` — OpenSAH
- `sahcore` — SAH Core
- `sahconnect` — SAH Connect
- `sahlink` — SAH Link
- `sahapi` — SAH API

The `adssh` binary, module path `github.com/afterdarksys/adssh`, import paths, binaries `adssh` and `adssh-mcp`, and the GitHub repository stay on the development name until a move is explicit. A brand rename is not required for the SAH utilities to exist. GitHub will redirect a renamed repo. The Go module path will not.

Current code, until that move:

- Shell: `~/development/adssh`
- System control plane, agent, CLI, and REST drivers: `~/development/systemapi.io`
- Compute catalog: `~/development/computeapi.io`

OAuth2 device login lives in `~/development/systemapi.io` (`controlplane/oauth.js`). `sahapi` is a loopback allowlisted GET proxy and does not host OAuth. Dashboard login is Authentik at `auth.afterdarksys.com`.

## Product vision

Recorded 2026-10-12. The ecosystem is seven names:

- `opensah` — OpenSAH
- `sahlink` — SAH Link
- `sahcore` — SAH Core
- `sahconnect` — SAH Connect
- `sahapi` — SAH API
- `computeapi.io`
- `systemapi.io`

The **sah** suite can be a joint systemapi + computeapi product. That is a product boundary, not a repo merge. `adssh`, `systemapi.io`, and `computeapi.io` stay their own repositories. Do not merge them from this note.

Roles recorded 2026-10-12, from Ryan. The four tools below are the 0.1.0 programs built that day. They are the entrypoints, not a finished platform. The suite contract is `~/development/systemapi.io/docs/sah-suite.md`.

- `opensah` — initial, specific tooling. `version`, `tools`, and `ready`.
- `sahconnect` — SSH and API client. Execs `adssh`. Calls systemapi over HTTP.
- `sahapi` — API service. Loopback allowlisted GET proxy. OAuth stays in systemapi.
- `sahlink` — test and debug utility. Starts a program and records stdin, stderr, and stdout. An opt-in loopback relay dials one named upstream. It can read and write those streams. It does not attach to an existing PID and it does not ptrace.
- `sahcore` — not assigned. Documentation only. No binary.

`adssh` stays the execution shell under its development name. It is not renamed into one of those utilities.

**adssh** is the execution environment. Scripted shell, policy, break-glass, and native SSH when policy allows it. It already has a local admin HTTP API. It is not the fleet website and it does not provision machines.

**systemapi.io** is the website, client, and server for managing Linux systems. A host is an API resource. The agent phones home. Later use is the API, the CLI, and the web terminal. MacOS support is a goal. The agent has Darwin branches for software inventory and PTY. MacOS is not a managed platform yet. Human login for the site is Authentik.

**computeapi.io** requests compute and provisions it through an API and a CLI. Google, Azure, Amazon, and Oracle are the target clouds. Bare metal is required: allocate capacity from bare-metal systems with Docker and k3s. Today the wired compute adapters are Vast.ai and io.net GPU offers. AWS, GCP, and Oracle appear as storage provider names. There is no Azure, k3s, or bare-metal allocator in the Go API yet.

Handoff, when a machine is real: computeapi provisions it, the machine enrolls through systemapi, and adssh executes on it under policy and a lease. computeapi does not grow its own shell. systemapi does not open inbound SSH by default.
