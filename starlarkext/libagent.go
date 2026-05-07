package starlarkext

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	toml "github.com/pelletier/go-toml/v2"
	"go.starlark.net/starlark"
)

type agentFrontmatter struct {
	Name      string   `toml:"name"`
	Model     string   `toml:"model"`
	MCPServer string   `toml:"mcp_server"`
	Tools     []string `toml:"tools"`
}

// parseAgentFile splits a TOML +++ frontmatter + markdown body agent file into its components.
func parseAgentFile(content string) (agentFrontmatter, string, error) {
	// File format: +++\n<toml>\n+++\n<markdown body>
	// Use SplitN with limit 3 so +++ appearing in the body does not cause extra splits.
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

// createLoadAgent creates the sys.load_agent Starlark builtin.
// It reads an agent definition file from ~/.adssh/agents/<name>.md,
// parses its TOML frontmatter and markdown system prompt, initialises an
// Anthropic API client, and returns a stateful callable that maintains
// conversation history for the lifetime of the Starlark session.
func createLoadAgent(env starlark.StringDict) *starlark.Builtin {
	// env is reserved for future injection of Starlark globals into agent tool calls.
	_ = env
	return starlark.NewBuiltin("load_agent", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name string
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name); err != nil {
			return starlark.None, err
		}

		// Path traversal guard: reject names containing / or .. before filepath.Join.
		if strings.Contains(name, "/") || strings.Contains(name, "..") {
			return starlark.None, fmt.Errorf("invalid agent name: must not contain path separators")
		}

		home, err := os.UserHomeDir()
		if err != nil {
			return starlark.None, fmt.Errorf("cannot determine home directory: %v", err)
		}
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

		// Model resolution: ADSSHA_MODEL env > frontmatter model > hardcoded default (D-04).
		model := os.Getenv("ADSSHA_MODEL")
		if model == "" {
			model = fm.Model
		}
		if model == "" {
			model = "claude-sonnet-4-6"
		}

		client := anthropic.NewClient(option.WithAPIKey(apiKey))
		history := []anthropic.MessageParam{}

		// Return a stateful inner callable that closes over client, history, model,
		// and systemPrompt. Each call appends to history, maintaining multi-turn
		// conversation state for the lifetime of this Starlark session (D-02, D-08).
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
			// Guard: extract text from the first TextBlock only.
			var text string
			for _, block := range resp.Content {
				if block.Type == "text" {
					text = block.Text
					break
				}
			}
			if text == "" {
				return nil, fmt.Errorf("agent response contained no text block (stop_reason: %s, first block type: %s)", resp.StopReason, resp.Content[0].Type)
			}
			history = append(history, resp.ToParam())
			return starlark.String(text), nil
		}), nil
	})
}
