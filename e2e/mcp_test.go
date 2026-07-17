//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// jsonRPCRequest is a minimal JSON-RPC 2.0 request/notification envelope.
type jsonRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id,omitempty"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// jsonRPCResponse is a minimal JSON-RPC 2.0 response envelope.
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// mcpClient is a minimal newline-delimited JSON-RPC client speaking to
// adssh-mcp over its stdio transport (mark3labs/mcp-go frames each message as
// a single JSON object terminated by '\n').
type mcpClient struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	nextID int
}

// startMCP launches adssh-mcp with the sandbox env and returns a client.
func startMCP(t *testing.T, env []string) *mcpClient {
	t.Helper()
	cmd := exec.Command(mcpBin)
	cmd.Env = env
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	// Drain stderr so the child never blocks on a full pipe.
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	go func() { _, _ = io.Copy(io.Discard, stderr) }()

	if err := cmd.Start(); err != nil {
		t.Fatalf("start adssh-mcp: %v", err)
	}
	c := &mcpClient{t: t, cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout), nextID: 1}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return c
}

// call sends a request and reads the matching response (with a timeout).
func (c *mcpClient) call(method string, params interface{}) jsonRPCResponse {
	c.t.Helper()
	id := c.nextID
	c.nextID++
	req := jsonRPCRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params}
	c.writeMessage(req)
	return c.readResponse()
}

// notify sends a notification (no id, no response expected).
func (c *mcpClient) notify(method string, params interface{}) {
	c.t.Helper()
	req := jsonRPCRequest{JSONRPC: "2.0", Method: method, Params: params}
	c.writeMessage(req)
}

func (c *mcpClient) writeMessage(v interface{}) {
	c.t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		c.t.Fatalf("marshal request: %v", err)
	}
	b = append(b, '\n')
	if _, err := c.stdin.Write(b); err != nil {
		c.t.Fatalf("write request: %v", err)
	}
}

func (c *mcpClient) readResponse() jsonRPCResponse {
	c.t.Helper()
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := c.stdout.ReadString('\n')
		ch <- result{line: line, err: err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	select {
	case <-ctx.Done():
		c.t.Fatalf("timed out waiting for MCP response")
	case r := <-ch:
		if r.err != nil && strings.TrimSpace(r.line) == "" {
			c.t.Fatalf("read response: %v", r.err)
		}
		var resp jsonRPCResponse
		if err := json.Unmarshal([]byte(r.line), &resp); err != nil {
			c.t.Fatalf("decode response %q: %v", r.line, err)
		}
		return resp
	}
	return jsonRPCResponse{}
}

// callToolText extracts the concatenated text content and isError flag from a
// tools/call result.
func callToolText(t *testing.T, resp jsonRPCResponse) (text string, isError bool) {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %d %s", resp.Error.Code, resp.Error.Message)
	}
	var res struct {
		IsError bool `json:"isError"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatalf("decode tool result: %v (%s)", err, string(resp.Result))
	}
	var sb strings.Builder
	for _, ct := range res.Content {
		sb.WriteString(ct.Text)
	}
	return sb.String(), res.IsError
}

// TestMCPRoundTrip drives the MCP server over raw stdio JSON-RPC: initialize,
// tools/list, then tools/call for eval_starlark (allowed) and run_shell
// (denied by policy). It asserts the policy gate returns the denied tool as an
// error result while the allowed tool executes normally.
func TestMCPRoundTrip(t *testing.T) {
	sb := newSandbox(t)
	// Policy: allow everything except the run_shell MCP tool (policyGate builds
	// its PolicyContext with command == tool name).
	sb.writePolicy(`package adssh.authz

default allow = true
default deny_reason = ""

allow = false {
    input.command == "run_shell"
}

deny_reason = "run_shell disabled by e2e policy" {
    input.command == "run_shell"
}
`)

	c := startMCP(t, sb.env(""))

	// initialize
	initResp := c.call("initialize", map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]interface{}{},
		"clientInfo":      map[string]interface{}{"name": "adssh-e2e", "version": "0.0.1"},
	})
	if initResp.Error != nil {
		t.Fatalf("initialize error: %d %s", initResp.Error.Code, initResp.Error.Message)
	}
	if len(initResp.Result) == 0 {
		t.Fatalf("initialize returned empty result")
	}
	c.notify("notifications/initialized", map[string]interface{}{})

	// tools/list
	listResp := c.call("tools/list", map[string]interface{}{})
	if listResp.Error != nil {
		t.Fatalf("tools/list error: %d %s", listResp.Error.Code, listResp.Error.Message)
	}
	var tools struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(listResp.Result, &tools); err != nil {
		t.Fatalf("decode tools/list: %v", err)
	}
	got := map[string]bool{}
	names := make([]string, 0, len(tools.Tools))
	for _, tl := range tools.Tools {
		got[tl.Name] = true
		names = append(names, tl.Name)
	}
	for _, want := range []string{"eval_starlark", "run_shell", "audit_log"} {
		if !got[want] {
			t.Fatalf("tools/list missing %q; got %v", want, names)
		}
	}

	// tools/call eval_starlark (allowed)
	evalResp := c.call("tools/call", map[string]interface{}{
		"name":      "eval_starlark",
		"arguments": map[string]interface{}{"code": `print("MCP_EVAL_OK")`},
	})
	evalText, evalErr := callToolText(t, evalResp)
	if evalErr {
		t.Fatalf("eval_starlark returned error result: %s", evalText)
	}
	if !strings.Contains(evalText, "MCP_EVAL_OK") {
		t.Fatalf("eval_starlark output missing marker, got %q", evalText)
	}

	// tools/call run_shell (denied by policy)
	shellResp := c.call("tools/call", map[string]interface{}{
		"name":      "run_shell",
		"arguments": map[string]interface{}{"command": "echo should-be-denied"},
	})
	shellText, shellErr := callToolText(t, shellResp)
	if !shellErr {
		t.Fatalf("expected run_shell to be denied (isError=true), got success: %q", shellText)
	}
	if !strings.Contains(shellText, "access denied") {
		t.Fatalf("expected 'access denied' in denied tool result, got %q", shellText)
	}
}
