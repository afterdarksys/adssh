# Phase 4: ADSSHA Agent - Pattern Map

**Mapped:** 2026-05-07
**Files analyzed:** 5 (3 new, 2 modified)
**Analogs found:** 4 / 5 (agents/adssha.md has no codebase analog — static markdown file)

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `agents/adssha.md` | config/static | N/A | `.claude/skills/adssh/SKILL.md` | partial (same concept, different format) |
| `starlarkext/libagent.go` | service | request-response | `starlarkext/libmod.go` | exact (factory + Starlark builtin) |
| `starlarkext/starlarkext.go` | config | N/A | self (modify line 62 block) | exact (self-referential inject) |
| `go.mod` / `go.sum` | config | N/A | self (existing require block) | exact |
| `starlarkext/libagent_test.go` | test | N/A | none | no analog |

---

## Pattern Assignments

### `agents/adssha.md` (config, static)

**Analog:** `.claude/skills/adssh/SKILL.md` (partial — same agent-definition concept; different delimiter/parser)

**Frontmatter format** — TOML `+++` delimiters (NOT YAML `---` like SKILL.md):
```toml
+++
name = "adssha"
model = "claude-sonnet-4-6"
mcp_server = "adssh"
tools = ["eval_starlark", "run_shell", "list_sessions", "cloud_query", "container_exec", "audit_log"]
+++
```

**SKILL.md frontmatter for reference** (`.claude/skills/adssh/SKILL.md` lines 1-7 — do NOT copy this format):
```yaml
---
name: adssh
description: |
  ...
triggers:
  - /adssh
---
```

**Key distinction:** `agents/adssha.md` uses TOML `+++`. SKILL.md uses YAML `---`. These are parsed by different code. Do not mix them.

**Body structure** (plain markdown after closing `+++`):
- Identity statement: "You are ADSSHA, a DevOps AI embedded in the adssh shell."
- Tool catalogue: one section per tool — `eval_starlark`, `run_shell`, `list_sessions`, `cloud_query`, `container_exec`, `audit_log` — with when/how to use each.
- Autonomy rules: read-only ops run freely; destructive/state-changing ops describe plan + ask confirmation before executing.
- Error handling: name exact failure, show what `audit_log` contains, suggest concrete recovery (e.g., "check policy.rego line N").
- Multi-step workflow examples: list sessions → query cloud state → run diagnostic scripts → review audit log.

---

### `starlarkext/libagent.go` (service, request-response)

**Analog:** `starlarkext/libmod.go` — exact structural match (builtin factory pattern)

**Package declaration + imports pattern** (mirrors `starlarkext/libmod.go` lines 1-7):
```go
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
```

**Factory function signature** (mirrors `starlarkext/libmod.go` lines 15-16):
```go
// createLoadPlugin pattern — exact structural template:
func createLoadPlugin(globals starlark.StringDict) *starlark.Builtin {
    return starlark.NewBuiltin("load_plugin", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
        var path string
        if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &path); err != nil {
            return starlark.None, err
        }
        // ... resource loading ...
        return starlark.True, nil
    })
}

// createLoadAgent follows this EXACT same structure:
func createLoadAgent(env starlark.StringDict) *starlark.Builtin {
    return starlark.NewBuiltin("load_agent", func(...) (starlark.Value, error) {
        var name string
        if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name); err != nil {
            return starlark.None, err
        }
        // ... file loading, parsing, client init ...
        return starlark.NewBuiltin("agent", agentFunc), nil  // returns callable, not bool
    })
}
```

**UnpackArgs arg name convention** (from `starlarkext/libmod.go` line 18 and `starlarkext/exec.go` lines 20, 49):
```go
// load_plugin uses "path", exec_cmd uses "cmd" — load_agent uses "name"
if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name); err != nil {
    return starlark.None, err
}
```

**Error return convention** (from `starlarkext/libmod.go` lines 23-25, 28-30):
```go
// Always return starlark.None (not nil) as first value on error in outer factory:
return starlark.None, fmt.Errorf("agent %q not found — copy agents/%s.md to %s", name, name, path)

// Return nil (not starlark.None) as first value on error in inner callable:
return nil, fmt.Errorf("agent API error: %v", err)
```

**Home directory expansion** (from `config/env.go` lines 47-48):
```go
home, _ := os.UserHomeDir()
adsshDir := filepath.Join(home, ".adssh")
// For agent: filepath.Join(home, ".adssh", "agents", name+".md")
```

**Env var reading pattern** (from `config/env.go` lines 51-62):
```go
// config/env.go uses envOr() helper; in libagent.go inline the same logic:
apiKey := os.Getenv("ANTHROPIC_API_KEY")
if apiKey == "" {
    return starlark.None, fmt.Errorf("ANTHROPIC_API_KEY not set")
}
model := os.Getenv("ADSSHA_MODEL")
if model == "" {
    model = fm.Model  // fall back to frontmatter, then hardcoded default
}
if model == "" {
    model = "claude-sonnet-4-6"
}
```

**Inner callable (closure over state)** — secondary analog from `starlarkext/exec.go` lines 17-43:
```go
// createExecCmd returns a raw function (not *starlark.Builtin); createLoadAgent
// returns starlark.NewBuiltin("agent", func...) — same closure-over-state concept:
func createExecCmd(globals starlark.StringDict, restricted bool) func(...) (starlark.Value, error) {
    return func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
        // ... uses globals from outer scope ...
    }
}
```

**TOML frontmatter struct** (go-toml/v2 tag convention):
```go
type agentFrontmatter struct {
    Name      string   `toml:"name"`
    Model     string   `toml:"model"`
    MCPServer string   `toml:"mcp_server"`
    Tools     []string `toml:"tools"`
}
```

**File parsing** (use SplitN with limit 3 to handle `+++` in body):
```go
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

**Anthropic API call pattern** (from RESEARCH.md verified against SDK source):
```go
// history is []anthropic.MessageParam closed over by the agent callable
history = append(history, anthropic.NewUserMessage(anthropic.NewTextBlock(task)))
resp, err := client.Messages.New(context.Background(), anthropic.MessageNewParams{
    MaxTokens: 4096,
    Model:     anthropic.Model(model),
    System:    []anthropic.TextBlockParam{{Text: systemPrompt}},  // NOT a string field
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
```

**Security — path traversal validation** (before constructing file path):
```go
if strings.Contains(name, "/") || strings.Contains(name, "..") {
    return starlark.None, fmt.Errorf("invalid agent name: must not contain path separators")
}
```

---

### `starlarkext/starlarkext.go` (config, modify)

**Injection point** (`starlarkext/starlarkext.go` lines 59-72 — sysDict block):
```go
// Sys
sysDict := starlark.NewDict(8)
sysDict.SetKey(starlark.String("getenv"), starlark.NewBuiltin("getenv", builtinGetEnv))
sysDict.SetKey(starlark.String("setenv"), starlark.NewBuiltin("setenv", builtinSetEnv))
sysDict.SetKey(starlark.String("load_plugin"), createLoadPlugin(env))   // line 62 — existing
// INSERT AFTER LINE 62:
sysDict.SetKey(starlark.String("load_agent"), createLoadAgent(env))     // new line
if !restricted {
    sysDict.SetKey(starlark.String("read_file"), ...)
    // ...
}
```

**Gate decision:** `load_plugin` at line 62 is NOT inside the `if !restricted` block. `load_agent` must be placed in the same unconditional position (after line 62, before the `if !restricted {` at line 63). This makes `sys.load_agent` available in restricted and unrestricted sessions alike — matching the `load_plugin` precedent.

**sysDict size:** Currently initialized with `starlark.NewDict(8)`. After adding `load_agent`, increment to `starlark.NewDict(9)` (or leave — Go maps auto-resize; this is just an initial capacity hint).

---

### `go.mod` / `go.sum` (config, modify)

**Existing direct dependency pattern** (`go.mod` lines 5-29 — require block format):
```
require (
    github.com/aws/aws-sdk-go-v2 v1.41.7
    ...
    gopkg.in/yaml.v3 v3.0.1
)
```

**What changes:**
1. Add `github.com/anthropics/anthropic-sdk-go v1.41.0` to the direct `require` block (via `go get github.com/anthropics/anthropic-sdk-go@latest`).
2. Promote `github.com/pelletier/go-toml/v2` from indirect to direct by importing it in `libagent.go` and running `go mod tidy`.

**Note:** `go.sum` is updated automatically by `go get` and `go mod tidy` — do not edit by hand. pelletier/go-toml/v2 is confirmed absent from go.sum currently (grep found no entry). Running `go get github.com/pelletier/go-toml/v2` explicitly will add it.

---

### `starlarkext/libagent_test.go` (test)

**Analog:** None — no test files exist in `starlarkext/`. This is the first test file in the package.

**Go test file convention** (standard Go testing, consistent with `go test ./starlarkext/...`):
```go
package starlarkext

import (
    "testing"
)

func TestParseAgentFile(t *testing.T) {
    // Test valid frontmatter + body
    // Test missing delimiters → error
    // Test invalid TOML → error
    // Test body trimming
}

func TestLoadAgentNotFound(t *testing.T) {
    // Test helpful error message when ~/.adssh/agents/notexist.md is absent
}

func TestLoadAgentPathTraversal(t *testing.T) {
    // Test that "../etc/passwd" returns error
    // Test that "foo/bar" returns error
}
```

**No API key required** for unit tests of `parseAgentFile` and path validation — those tests run without credentials. The integration test (`TestLoadAgentRoundTrip`) requires `ANTHROPIC_API_KEY` and is skipped if absent:
```go
func TestLoadAgentRoundTrip(t *testing.T) {
    if os.Getenv("ANTHROPIC_API_KEY") == "" {
        t.Skip("ANTHROPIC_API_KEY not set")
    }
    // ...
}
```

---

## Shared Patterns

### Home Directory Expansion
**Source:** `config/env.go` lines 47-48
**Apply to:** `starlarkext/libagent.go` (path construction for `~/.adssh/agents/`)
```go
home, _ := os.UserHomeDir()
path := filepath.Join(home, ".adssh", "agents", name+".md")
```

### Env Var with Default
**Source:** `config/env.go` lines 67-72 (`envOr` helper)
**Apply to:** `starlarkext/libagent.go` (ADSSHA_MODEL fallback)
```go
func envOr(key, defaultVal string) string {
    if v := os.Getenv(key); v != "" {
        return v
    }
    return defaultVal
}
// In libagent.go — inline equivalent (no need to call config.envOr; it's unexported):
model := os.Getenv("ADSSHA_MODEL")
if model == "" {
    model = fm.Model
}
```

### Starlark Builtin Factory
**Source:** `starlarkext/libmod.go` lines 15-43 (`createLoadPlugin`)
**Apply to:** `starlarkext/libagent.go` (`createLoadAgent`)
```go
func createLoadPlugin(globals starlark.StringDict) *starlark.Builtin {
    return starlark.NewBuiltin("load_plugin", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
        var path string
        if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &path); err != nil {
            return starlark.None, err
        }
        // ... open resource ...
        return starlark.True, nil
    })
}
```

### sysDict SetKey Injection
**Source:** `starlarkext/starlarkext.go` line 62
**Apply to:** Same file, immediately after line 62
```go
sysDict.SetKey(starlark.String("load_plugin"), createLoadPlugin(env))
sysDict.SetKey(starlark.String("load_agent"), createLoadAgent(env))  // add here
```

---

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `starlarkext/libagent_test.go` | test | N/A | No test files exist in starlarkext/ package — this is the first |
| `agents/adssha.md` (body/system prompt) | config | N/A | No existing agent system prompt in repo to copy from; write from scratch per D-09/D-10/D-11 decisions |

---

## Metadata

**Analog search scope:** `starlarkext/`, `config/`, `.claude/skills/`, `go.mod`
**Files read:** `starlarkext/libmod.go`, `starlarkext/starlarkext.go`, `starlarkext/exec.go`, `config/env.go`, `go.mod`, `.claude/skills/adssh/SKILL.md`
**Pattern extraction date:** 2026-05-07

**Critical implementation notes for planner:**
1. `pelletier/go-toml/v2` is NOT confirmed in go.sum — planner must include `go get github.com/pelletier/go-toml/v2` as a Wave 0 step alongside `go get github.com/anthropics/anthropic-sdk-go@latest`.
2. `anthropic.MessageNewParams.System` is `[]anthropic.TextBlockParam`, not a string — compile error if wrong.
3. Use `strings.SplitN(..., 3)` not `strings.Split` for frontmatter extraction — body may contain `+++`.
4. `load_agent` goes before `if !restricted {` at line 63 of `starlarkext.go` — same gate level as `load_plugin`.
5. Path traversal check on `name` parameter must run before `filepath.Join`.
