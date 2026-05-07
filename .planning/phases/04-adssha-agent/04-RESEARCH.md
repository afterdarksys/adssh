# Phase 4: ADSSHA Agent - Research

**Researched:** 2026-05-07
**Domain:** Anthropic Go SDK, TOML frontmatter parsing, Starlark callable pattern
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** ADSSHA is both inbound (agents/adssha.md read by Claude) and outbound (adssh calls Claude API via sys.load_agent).
- **D-02:** Callable maintains stateful conversation history per Starlark session (in-memory only).
- **D-03:** Returns a plain Starlark string (Claude text response).
- **D-04:** Env vars only: `ANTHROPIC_API_KEY` (required), `ADSSHA_MODEL` (optional, default: `claude-sonnet-4-6`).
- **D-05:** Markdown with TOML `+++` frontmatter. Frontmatter: `name`, `model`, `mcp_server`, `tools`. Body: system prompt in plain markdown.
- **D-06:** Runtime path: `~/.adssh/agents/{name}.md`. Distributed copy: `agents/adssha.md` in repo root.
- **D-07:** `sys.load_agent("adssha")` reads file, parses frontmatter + body, initializes history with system prompt, returns Starlark callable.
- **D-08:** History scoped to Starlark session, not persisted.
- **D-09:** Autonomy: read-only ops run freely; destructive ops describe plan + ask confirmation.
- **D-10:** Primary job: multi-step DevOps workflow orchestration (chain tools: list sessions → cloud query → diagnostics → audit log).
- **D-11:** Error handling: name exact failure, show audit_log, suggest recovery path.

### Claude's Discretion

- Exact Go struct layout for conversation history (implementer decides).
- Call pattern for the returned Starlark callable follows `sys.load_plugin` pattern.

### Deferred Ideas (OUT OF SCOPE)

- Persisting conversation history to disk.
- Multiple concurrent agent instances.
- Agent tool call interception / policy enforcement at the callable level.
- Proactive monitoring mode.
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| AGENT-01 | ADSSHA agent definition (system prompt + MCP tool bindings) is written | agents/adssha.md with TOML frontmatter + markdown body covering all 6 MCP tools |
| AGENT-02 | Agent acts as a DevOps AI assistant with shell and cloud access via MCP tools | System prompt in adssha.md teaches persona, tool usage, autonomy rules, error handling |
| AGENT-03 | Agent definition is loadable via `sys.load_agent("adssha")` in Starlark | createLoadAgent() Go builtin injected into sysDict in starlarkext.go |
</phase_requirements>

---

## Summary

Phase 4 has two distinct deliverables: a markdown agent definition file (`agents/adssha.md`) and a new Go builtin (`sys.load_agent`) in the Starlark extension system. Both are self-contained and neither requires changes to the MCP server binary, Rego engine, or SSH session handling.

The Go implementation follows an established pattern in `starlarkext/libmod.go` (`createLoadPlugin`) — read a path argument, open a resource, and return a `*starlark.Builtin`. The key difference is that `createLoadAgent` returns a stateful callable (not a boolean) that wraps an Anthropic API client and a conversation history slice.

The Anthropic Go SDK (`github.com/anthropics/anthropic-sdk-go`) is NOT yet in go.mod and must be added. The TOML parsing library (`github.com/pelletier/go-toml/v2`) IS already an indirect dependency (brought in transitively) and only needs to be promoted to a direct dependency in go.mod. No external services, databases, or infrastructure changes are required.

**Primary recommendation:** Add `github.com/anthropics/anthropic-sdk-go` via `go get`, promote `github.com/pelletier/go-toml/v2` to direct dependency, implement `createLoadAgent` mirroring `createLoadPlugin`'s structure, then write the agent definition file.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Agent definition file | Static file (repo + user home) | — | Pure markdown + TOML, no server involvement |
| TOML frontmatter parsing | Go process (starlarkext) | — | Happens at load time within the Starlark runtime |
| Anthropic API calls | Go process (starlarkext callable) | — | Outbound HTTP from within the adssh process |
| Conversation history | Go process (in-memory struct) | — | Scoped to Starlark thread lifetime, not persisted |
| sys.load_agent builtin | Go process (starlarkext) | — | Injected into sysDict alongside load_plugin |
| MCP tool usage | External (Claude via MCP protocol) | — | Inbound direction; adssha.md teaches Claude how to use them |

---

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `github.com/anthropics/anthropic-sdk-go` | v1.41.0 | Anthropic Claude API client | Official SDK; auto-reads ANTHROPIC_API_KEY from env; typed MessageParam/MessageNewParams |
| `github.com/pelletier/go-toml/v2` | v2.2.4 | TOML frontmatter parsing | Already in module graph (indirect); widely used; simple `toml.Unmarshal([]byte, &struct)` API |
| `go.starlark.net/starlark` | v0.0.0-20260326113308 | Starlark callable return type | Already project dependency; `*starlark.Builtin` is the return type |

**Version verification:** [VERIFIED: Go module proxy proxy.golang.org] — anthropic-sdk-go v1.41.0 published 2026-05-06. pelletier/go-toml v2.2.4 confirmed in go.sum (indirect).

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `os` (stdlib) | — | Read ANTHROPIC_API_KEY, expand `~/.adssh/agents/` path | Always — env var reads follow config/env.go pattern |
| `strings` (stdlib) | — | Split `+++` frontmatter delimiter from markdown body | Simple string split on `+++\n` |
| `context` (stdlib) | — | Pass to anthropic.Messages.New() | Required by SDK |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| pelletier/go-toml/v2 | BurntSushi/toml | BurntSushi not in module graph; pelletier is already present — no reason to add a new dependency |
| anthropic-sdk-go | Raw `net/http` | SDK handles auth headers, retry logic, typed structs — hand-rolling is never worth it here |
| `[]TextBlockParam` for system | string system | SDK v1.23.0 `MessageNewParams.System` field is `[]TextBlockParam` — must use struct form |

**Installation:**
```bash
go get github.com/anthropics/anthropic-sdk-go@latest
# pelletier/go-toml/v2 is already indirect — promote to direct:
go get github.com/pelletier/go-toml/v2
```

---

## Architecture Patterns

### System Architecture Diagram

```
Starlark session
  │
  ├─ sys.load_agent("adssha")
  │     │
  │     ├─ Read ~/.adssh/agents/adssha.md
  │     ├─ Split on +++ delimiter → TOML block + markdown body
  │     ├─ toml.Unmarshal → AgentFrontmatter{name, model, mcp_server, tools}
  │     ├─ Init history: []MessageParam (empty; system prompt passed per-call)
  │     └─ Return *starlark.Builtin (agentCallable wrapping client + history + systemPrompt)
  │
  └─ agent("deploy staging")
        │
        ├─ Append NewUserMessage(task) to history
        ├─ client.Messages.New(ctx, MessageNewParams{
        │     Model:     agentFrontmatter.model,
        │     MaxTokens: 4096,
        │     System:    []TextBlockParam{{Text: systemPrompt}},
        │     Messages:  history,
        │  })
        ├─ Extract response.Content[0].Text
        ├─ Append response.ToParam() to history
        └─ Return starlark.String(text)
```

### Recommended Project Structure

```
agents/
└── adssha.md           # Canonical agent definition (committed to repo)

starlarkext/
├── starlarkext.go      # Add: sysDict.SetKey("load_agent", createLoadAgent(env))
└── libagent.go         # New file: createLoadAgent(), agentCallable struct
```

Note: `libagent.go` is the suggested filename following the `libmod.go` naming convention. The planner may choose `agent.go` or another name at discretion.

### Pattern 1: createLoadAgent — Mirrors createLoadPlugin

**What:** A `*starlark.Builtin` factory that reads the agent file path argument, parses it, and returns a stateful callable.

**When to use:** Exactly once — called at `SetupExtensions` time to create the `sys.load_agent` builtin.

**Example:**
```go
// Source: verified against starlarkext/libmod.go pattern + anthropic-sdk-go@v1.23.0

type AgentFrontmatter struct {
    Name      string   `toml:"name"`
    Model     string   `toml:"model"`
    MCPServer string   `toml:"mcp_server"`
    Tools     []string `toml:"tools"`
}

type agentCallable struct {
    client       *anthropic.Client
    systemPrompt string
    model        string
    history      []anthropic.MessageParam
}

func (a *agentCallable) CallInternal(thread *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
    var task string
    if err := starlark.UnpackArgs("agent", args, kwargs, "task", &task); err != nil {
        return nil, err
    }
    a.history = append(a.history, anthropic.NewUserMessage(anthropic.NewTextBlock(task)))
    resp, err := a.client.Messages.New(context.Background(), anthropic.MessageNewParams{
        MaxTokens: 4096,
        Model:     anthropic.Model(a.model),
        System:    []anthropic.TextBlockParam{{Text: a.systemPrompt}},
        Messages:  a.history,
    })
    if err != nil {
        return nil, fmt.Errorf("agent API error: %v", err)
    }
    text := resp.Content[0].Text
    a.history = append(a.history, resp.ToParam())
    return starlark.String(text), nil
}
```

**Note on Starlark callable:** `*starlark.Builtin` requires a function signature. For stateful callables, the pattern is to capture state in a closure or use a custom type implementing `starlark.Callable`. The closure approach is simpler and follows `createExecCmd` in `starlarkext.go`:

```go
func createLoadAgent(env starlark.StringDict) *starlark.Builtin {
    return starlark.NewBuiltin("load_agent", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
        var name string
        if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name); err != nil {
            return starlark.None, err
        }
        // ... parse file, init client ...
        // Return a new builtin that closes over per-agent state
        ac := &agentCallable{ /* ... */ }
        return starlark.NewBuiltin("agent", ac.CallInternal), nil
    })
}
```

### Pattern 2: TOML Frontmatter Extraction

**What:** Split the markdown file on `+++` delimiters, decode the TOML block, treat the remainder as the system prompt.

**When to use:** Inside `createLoadAgent`, once, at load time.

**Example:**
```go
// Source: verified against pelletier/go-toml/v2@v2.2.4 Unmarshal API
import "github.com/pelletier/go-toml/v2"

func parseAgentFile(content string) (AgentFrontmatter, string, error) {
    // File format: +++\n<toml>\n+++\n<markdown body>
    parts := strings.SplitN(content, "+++\n", 3)
    if len(parts) < 3 {
        return AgentFrontmatter{}, "", fmt.Errorf("invalid agent file: missing +++ frontmatter delimiters")
    }
    tomlBlock := parts[1]
    body := strings.TrimSpace(parts[2])

    var fm AgentFrontmatter
    if err := toml.Unmarshal([]byte(tomlBlock), &fm); err != nil {
        return AgentFrontmatter{}, "", fmt.Errorf("frontmatter parse error: %v", err)
    }
    return fm, body, nil
}
```

**Note:** The file starts with `+++\n` so `strings.SplitN(content, "+++\n", 3)` yields `["", tomlBlock, markdownBody]`. Verify this split logic handles the exact delimiter: `+++` followed by `\n`.

### Pattern 3: sysDict Injection

**What:** Add `load_agent` to the `sys` dict exactly like `load_plugin`.

**When to use:** In `SetupExtensions`, inside the `sysDict` block.

**Example:**
```go
// Source: verified against starlarkext/starlarkext.go lines 59-72
sysDict.SetKey(starlark.String("load_agent"), createLoadAgent(env))
```

This line goes after line 62 (`load_plugin`) in `starlarkext.go`. It is NOT restricted behind the `!restricted` gate — `sys.load_plugin` is not gated either. [VERIFIED: reading starlarkext.go]

### Pattern 4: Model and API Key Resolution

**What:** Read env vars at callable-invocation time (not at `load_agent` time), matching config/env.go convention.

**When to use:** Inside the load_agent builtin factory.

**Example:**
```go
// Source: verified against config/env.go envOr() pattern
apiKey := os.Getenv("ANTHROPIC_API_KEY")
if apiKey == "" {
    return starlark.None, fmt.Errorf("ANTHROPIC_API_KEY not set")
}
model := os.Getenv("ADSSHA_MODEL")
if model == "" {
    model = "claude-sonnet-4-6"
}
client := anthropic.NewClient(option.WithAPIKey(apiKey))
```

Note: `anthropic.NewClient()` with no args reads `ANTHROPIC_API_KEY` automatically from env. Explicit `option.WithAPIKey` is clearer and matches the pattern of reading config explicitly, but either works. [VERIFIED: anthropic-sdk-go README + SDK source]

### Anti-Patterns to Avoid

- **Global client:** Don't create one `anthropic.Client` at `SetupExtensions` time. Client is cheap to create; initialize it inside the load_agent factory per agent instance so API key changes take effect.
- **Storing system prompt in Messages history:** The Anthropic API's `Messages` array does not support a "system" role. System prompt belongs in `MessageNewParams.System []TextBlockParam`. Storing it in the messages slice causes API errors.
- **`strings.Split` without limit:** Use `strings.SplitN(content, "+++\n", 3)` not `strings.Split` — an unanchored split breaks if the system prompt body contains `+++`.
- **Panicking on empty Content:** `resp.Content[0].Text` panics if Content is empty (e.g., on stop_reason=max_tokens with no output). Always check `len(resp.Content) > 0`.
- **Not promoting go-toml/v2 to direct:** Running `go mod tidy` after adding anthropic-sdk-go may drop the indirect dependency marker. Explicitly import pelletier/go-toml/v2 in `libagent.go` and it will be promoted automatically.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Anthropic API client | Custom `net/http` with auth headers | `anthropic-sdk-go` | SDK handles: auth, retries, timeout, typed params, content extraction helpers |
| TOML parsing | Custom `+++` parser with string splitting | `pelletier/go-toml/v2` | Edge cases: multiline strings, arrays, escape sequences in TOML values |
| Message history format | Custom JSON struct for conversation | `[]anthropic.MessageParam` + `response.ToParam()` | SDK provides typed round-trip: `NewUserMessage()` → `resp.ToParam()` → next request |
| Model constant | Hardcoded string | `anthropic.ModelClaudeSonnet4_6` | SDK defines all model IDs as typed constants; prevents typos |

**Key insight:** The TOML and HTTP layers both have deceptively many edge cases. The TOML library is already in the module graph — using it costs nothing.

---

## Runtime State Inventory

Step 2.5: SKIPPED — this is a greenfield phase adding new files and a new builtin. No rename/refactor/migration involved. No existing runtime state references the name "adssha agent" as a stored key, service config, or OS registration.

---

## Common Pitfalls

### Pitfall 1: SKILL.md Uses YAML `---`, Not TOML `+++`

**What goes wrong:** The Phase 3 SKILL.md (`.claude/skills/adssh/SKILL.md`) uses YAML `---` frontmatter. D-05 specifies TOML `+++` for the agent definition. These are different formats and different parsers. Mixing them up causes silent parse errors.

**Why it happens:** The CONTEXT.md says "mirrors the SKILL.md convention" but the SKILL.md actually uses YAML. The decisions clarify TOML `+++` for the agent — this is intentional (TOML fits structured metadata like arrays better than YAML for this use case).

**How to avoid:** `agents/adssha.md` uses `+++` delimiters with TOML. `.claude/skills/adssh/SKILL.md` uses `---` delimiters with YAML. They are different files with different parsers. [VERIFIED: reading existing SKILL.md]

**Warning signs:** `toml.Unmarshal` returning "key not found" or "cannot decode" on a file with `---` delimiters.

### Pitfall 2: MessageNewParams.System is `[]TextBlockParam`, Not `string`

**What goes wrong:** Passing `System: string` won't compile. The SDK field is `System []TextBlockParam`.

**Why it happens:** Older Anthropic SDK versions used a string system prompt. The Go SDK v1.23.0+ requires a slice of TextBlockParam.

**How to avoid:** Use `System: []anthropic.TextBlockParam{{Text: systemPrompt}}`. [VERIFIED: reading anthropic-sdk-go@v1.23.0/message.go line 9535]

**Warning signs:** Compile error "cannot use string as []TextBlockParam".

### Pitfall 3: anthropic-sdk-go Not in go.mod

**What goes wrong:** `go build` fails with "no required module provides github.com/anthropics/anthropic-sdk-go".

**Why it happens:** The SDK is not a dependency of any existing package in the project. [VERIFIED: reading go.mod — no anthropic entry]

**How to avoid:** Run `go get github.com/anthropics/anthropic-sdk-go@latest` before writing code. The latest version as of 2026-05-06 is v1.41.0 (verified via module proxy). The cached version in GOPATH is v1.23.0 — `go get @latest` will fetch v1.41.0.

**Warning signs:** `go build: no required module`.

### Pitfall 4: Response Text Extraction

**What goes wrong:** `resp.Content[0].Text` panics if `resp.Content` is empty or if the first block is not a text block.

**Why it happens:** The API can return non-text content blocks (tool_use, thinking) or an empty content slice on error stop reasons.

**How to avoid:** Check `len(resp.Content) > 0` and check `resp.Content[0].Type == "text"` before accessing `.Text`. Alternative: iterate Content and collect all text blocks.

**Warning signs:** Index out of range panic at runtime.

### Pitfall 5: Home Directory Expansion

**What goes wrong:** `os.Open("~/.adssh/agents/adssha.md")` fails — Go does not expand `~` natively.

**Why it happens:** `~` is a shell convention, not a Go stdlib feature.

**How to avoid:** Use `os.UserHomeDir()` and `filepath.Join(home, ".adssh", "agents", name+".md")`. Follow the exact pattern in `config/env.go`. [VERIFIED: reading config/env.go]

**Warning signs:** "open ~/.adssh/agents/adssha.md: no such file or directory".

---

## Code Examples

### Full createLoadAgent skeleton (synthesized from verified patterns)

```go
// Source: patterns verified from starlarkext/libmod.go, starlarkext/starlarkext.go,
//         anthropic-sdk-go@v1.23.0/message.go, config/env.go, pelletier/go-toml/v2@v2.2.4

package starlarkext

import (
    "context"
    "fmt"
    "os"
    "path/filepath"
    "strings"

    "github.com/anthropics/anthropic-sdk-go"
    "github.com/anthropics/anthropic-sdk-go/option"
    "github.com/pelletier/go-toml/v2"
    "go.starlark.net/starlark"
)

type agentFrontmatter struct {
    Name      string   `toml:"name"`
    Model     string   `toml:"model"`
    MCPServer string   `toml:"mcp_server"`
    Tools     []string `toml:"tools"`
}

func createLoadAgent(env starlark.StringDict) *starlark.Builtin {
    return starlark.NewBuiltin("load_agent", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
        var name string
        if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name); err != nil {
            return starlark.None, err
        }

        home, _ := os.UserHomeDir()
        path := filepath.Join(home, ".adssh", "agents", name+".md")
        data, err := os.ReadFile(path)
        if err != nil {
            return starlark.None, fmt.Errorf("agent %q not found — copy agents/%s.md to %s", name, name, path)
        }

        fm, systemPrompt, err := parseAgentFile(string(data))
        if err != nil {
            return starlark.None, err
        }

        apiKey := os.Getenv("ANTHROPIC_API_KEY")
        if apiKey == "" {
            return starlark.None, fmt.Errorf("ANTHROPIC_API_KEY not set")
        }
        model := os.Getenv("ADSSHA_MODEL")
        if model == "" {
            model = fm.Model
        }
        if model == "" {
            model = "claude-sonnet-4-6"
        }

        client := anthropic.NewClient(option.WithAPIKey(apiKey))
        history := []anthropic.MessageParam{}

        return starlark.NewBuiltin("agent", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
            var task string
            if err := starlark.UnpackArgs(b.Name(), args, kwargs, "task", &task); err != nil {
                return nil, err
            }
            history = append(history, anthropic.NewUserMessage(anthropic.NewTextBlock(task)))
            resp, err := client.Messages.New(context.Background(), anthropic.MessageNewParams{
                MaxTokens: 4096,
                Model:     anthropic.Model(model),
                System:    []anthropic.TextBlockParam{{Text: systemPrompt}},
                Messages:  history,
            })
            if err != nil {
                return nil, fmt.Errorf("agent API error: %v", err)
            }
            if len(resp.Content) == 0 {
                return nil, fmt.Errorf("agent returned empty response (stop_reason: %s)", resp.StopReason)
            }
            text := resp.Content[0].Text
            history = append(history, resp.ToParam())
            return starlark.String(text), nil
        }), nil
    })
}

func parseAgentFile(content string) (agentFrontmatter, string, error) {
    parts := strings.SplitN(content, "+++\n", 3)
    if len(parts) < 3 {
        return agentFrontmatter{}, "", fmt.Errorf("invalid agent file: missing +++ frontmatter delimiters")
    }
    var fm agentFrontmatter
    if err := toml.Unmarshal([]byte(parts[1]), &fm); err != nil {
        return agentFrontmatter{}, "", fmt.Errorf("frontmatter parse error: %v", err)
    }
    return fm, strings.TrimSpace(parts[2]), nil
}
```

### agents/adssha.md frontmatter (confirmed tool names)

```toml
+++
name = "adssha"
model = "claude-sonnet-4-6"
mcp_server = "adssh"
tools = ["eval_starlark", "run_shell", "list_sessions", "cloud_query", "container_exec", "audit_log"]
+++
```

Tool names verified against `cmd/adssh-mcp/server.go`: `eval_starlark`, `run_shell`, `list_sessions`, `cloud_query`, `container_exec`, `audit_log`. [VERIFIED: reading server.go]

### starlarkext.go injection point

```go
// After line 62 (load_plugin), inside the sysDict block:
sysDict.SetKey(starlark.String("load_agent"), createLoadAgent(env))
```

NOT inside the `!restricted` gate — `load_plugin` itself is unconditional. [VERIFIED: reading starlarkext.go]

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| String system prompt in SDK | `[]TextBlockParam` slice | SDK v1.x | Must use struct — string form no longer compiles |
| `anthropic.ModelClaude3Sonnet` | `anthropic.ModelClaudeSonnet4_6` | SDK v1.23.0+ | Correct constant is `ModelClaudeSonnet4_6` |

**Model constants verified in SDK cache:**
- `ModelClaudeOpus4_6 = "claude-opus-4-6"` [VERIFIED: anthropic-sdk-go@v1.23.0]
- `ModelClaudeSonnet4_6 = "claude-sonnet-4-6"` [VERIFIED: anthropic-sdk-go@v1.23.0]

The default model `claude-sonnet-4-6` from D-04 matches the constant `anthropic.ModelClaudeSonnet4_6`.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `resp.Content[0].Text` is the correct field path for text extraction in anthropic-sdk-go | Code Examples | Compile error or runtime panic — verify against SDK version actually installed |
| A2 | `sys.load_agent` should NOT be behind the `!restricted` gate (same as `load_plugin`) | Code Examples | Agent callable available in restricted sessions — could be a security concern; confirm with Ryan |
| A3 | `anthropic-sdk-go v1.41.0` is backwards-compatible with v1.23.0 API surface used here | Standard Stack | Build failure if MessageNewParams fields changed between versions |

---

## Open Questions

1. **Restricted mode and `sys.load_agent`**
   - What we know: `sys.load_plugin` is unconditional (not gated by `!restricted`), so `sys.load_agent` would follow the same pattern.
   - What's unclear: Whether restricted Starlark sessions (SSH sessions from untrusted users) should be able to call the Anthropic API. This could be intentional (agent is useful to all users) or a security gap.
   - Recommendation: Default to matching `load_plugin` behavior (unconditional). If this is wrong, the planner should add a `if !restricted` gate.

2. **MaxTokens value**
   - What we know: D-03 says return a plain string; no max token was specified in decisions.
   - What's unclear: 4096 is used in the code example but not locked in decisions.
   - Recommendation: 4096 is a reasonable default for DevOps responses. Planner/implementer can expose it as a constant or env var later.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `github.com/anthropics/anthropic-sdk-go` | AGENT-03 (API calls) | ✗ not in go.mod | v1.41.0 available via proxy | None — must add via `go get` |
| `github.com/pelletier/go-toml/v2` | AGENT-03 (frontmatter parse) | ✓ indirect dep | v2.2.4 | Already in module graph |
| `ANTHROPIC_API_KEY` env var | AGENT-03 (runtime) | Unknown (user-set) | — | Runtime error with clear message |
| `~/.adssh/agents/` directory | AGENT-03 (runtime) | Created by user | — | `sys.load_agent` error with install instruction |

**Missing dependencies with no fallback:**
- `github.com/anthropics/anthropic-sdk-go` — must run `go get github.com/anthropics/anthropic-sdk-go@latest` as Wave 0 task

**Missing dependencies with fallback:**
- None

---

## Validation Architecture

`workflow.nyquist_validation` is not set in `.planning/config.json` — treating as enabled.

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Go testing (`go test ./...`) |
| Config file | none (standard Go test tooling) |
| Quick run command | `go test ./starlarkext/... -run TestLoadAgent -v` |
| Full suite command | `go test ./...` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| AGENT-01 | agents/adssha.md exists with valid TOML frontmatter + non-empty body | unit (file validation) | `go test ./starlarkext/... -run TestParseAgentFile` | ❌ Wave 0 |
| AGENT-02 | System prompt body covers all 6 tools, autonomy rules, error handling | manual review | N/A — content quality review | N/A |
| AGENT-03 | `sys.load_agent("adssha")` loads and returns a callable | integration | `go test ./starlarkext/... -run TestLoadAgent` | ❌ Wave 0 |

**Note:** AGENT-03 integration test requires a real `ANTHROPIC_API_KEY` for end-to-end verification. A unit test of the parse + callable creation path (without making API calls) can run without credentials.

### Sampling Rate

- **Per task commit:** `go build ./...` (compile check)
- **Per wave merge:** `go test ./starlarkext/... -v`
- **Phase gate:** `go test ./...` green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `starlarkext/libagent_test.go` — covers AGENT-01 (parseAgentFile), AGENT-03 (load_agent returns callable)
- [ ] `agents/adssha.md` — the agent definition file itself (Wave 0 creation, not a test gap)

---

## Security Domain

`security_enforcement` is not set to `false` in config.json — section is required.

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | Not applicable — no user auth in this builtin |
| V3 Session Management | no | Conversation history is in-memory, scoped to Starlark thread |
| V4 Access Control | partial | Restricted mode question (see Open Questions #1) — follow existing `!restricted` gate pattern |
| V5 Input Validation | yes | Agent name parameter: validate it is a safe filename (no path traversal: no `/`, `..`) |
| V6 Cryptography | no | API key passed via env var — no encryption needed in this code |

### Known Threat Patterns for This Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Path traversal in agent name | Tampering | Validate `name` contains no `/` or `..` before constructing path |
| API key leakage in error messages | Information Disclosure | Never include `apiKey` value in error strings |
| Prompt injection via task arg | Tampering | Out of scope for v1 — Rego enforces at the MCP layer; document as accepted risk |
| Unbounded history growth | DoS | In-memory only; bounded by session lifetime; acceptable for v1 |

**Path traversal mitigation example:**
```go
if strings.Contains(name, "/") || strings.Contains(name, "..") {
    return starlark.None, fmt.Errorf("invalid agent name: must not contain path separators")
}
```

---

## Sources

### Primary (HIGH confidence)

- `starlarkext/starlarkext.go` (local codebase) — sysDict structure, load_plugin placement, restricted gate
- `starlarkext/libmod.go` (local codebase) — createLoadPlugin pattern (exact template for createLoadAgent)
- `config/env.go` (local codebase) — env var pattern (envOr, UserHomeDir, isTruthy)
- `cmd/adssh-mcp/server.go` (local codebase) — confirmed 6 tool names: eval_starlark, run_shell, list_sessions, cloud_query, container_exec, audit_log
- `go.mod` (local codebase) — confirmed anthropic-sdk-go absent, pelletier/go-toml/v2 present as indirect
- `$GOPATH/pkg/mod/github.com/anthropics/anthropic-sdk-go@v1.23.0/message.go` — MessageNewParams struct, System field type `[]TextBlockParam`, MessageParam helpers
- `$GOPATH/pkg/mod/github.com/pelletier/go-toml/v2@v2.2.4/unmarshaler.go` — Unmarshal API signature
- Go module proxy `proxy.golang.org` — anthropic-sdk-go v1.41.0 published 2026-05-06

### Secondary (MEDIUM confidence)

- Context7 `/anthropics/anthropic-sdk-go` docs — multi-turn conversation pattern, client initialization, NewUserMessage/ToParam helpers
- `.claude/skills/adssh/SKILL.md` (local codebase) — confirmed Phase 3 SKILL.md uses YAML `---` not TOML `+++`

### Tertiary (LOW confidence)

- None

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — SDK version verified via module proxy; TOML library verified in module cache
- Architecture: HIGH — exact injection pattern verified by reading existing code
- Pitfalls: HIGH — verified directly from SDK source and existing codebase

**Research date:** 2026-05-07
**Valid until:** 2026-06-06 (30 days — stable Go SDK, stable pattern)
