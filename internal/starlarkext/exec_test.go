package starlarkext

import (
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
)

// execEnv builds the extension surface bound to a specific engine (so the exec_*
// builtins gate against THAT engine, not the process default) and wraps it with
// the govern layer, matching real session wiring.
func execEnv(t *testing.T, eng *security.Engine, restricted bool) starlark.StringDict {
	t.Helper()
	env := starlark.StringDict{}
	SetupExtensions(ExtensionOptions{Env: env, Restricted: restricted, Engine: eng})
	GovernStarlarkGlobalsInPlace(eng, env)
	return env
}

func allowAllEngine(t *testing.T) *security.Engine {
	t.Helper()
	eng, err := security.NewEngine(security.EngineConfig{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng
}

func evalExec(t *testing.T, env starlark.StringDict, src string) (starlark.StringDict, error) {
	t.Helper()
	return starlark.ExecFile(&starlark.Thread{Name: "exec-test"}, "t.star", src, env)
}

func TestExecCmdHappyPath(t *testing.T) {
	env := execEnv(t, allowAllEngine(t), false)
	g, err := evalExec(t, env, `out = sys["exec_cmd"]("echo hello")`)
	if err != nil {
		t.Fatalf("exec_cmd: %v", err)
	}
	got, _ := starlark.AsString(g["out"])
	if strings.TrimSpace(got) != "hello" {
		t.Fatalf("out = %q, want hello", got)
	}
}

// The exec builtins must gate their sub-commands against the SESSION engine, not
// the process default. A policy that denies the inner command must make the run
// fail closed, proving ExtensionOptions.Engine is threaded through.
func TestExecCmdGatedBySessionEngine(t *testing.T) {
	eng, err := security.NewEngine(security.EngineConfig{PolicySource: []byte(`
package adssh.authz
default allow = false
allow { input.command != "echo" }
deny_reason = "echo denied by session policy" { input.command == "echo" }
`)})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	env := execEnv(t, eng, false)
	_, err = evalExec(t, env, `out = sys["exec_cmd"]("echo hello")`)
	if err == nil {
		t.Fatal("expected exec_cmd to be denied by the session policy")
	}
	if !strings.Contains(err.Error(), "echo denied") {
		t.Fatalf("error = %v, want the session policy denial", err)
	}
}

// A hung command must fail closed at the timeout, not run forever.
func TestExecCmdTimeoutFailsClosed(t *testing.T) {
	env := execEnv(t, allowAllEngine(t), false)
	_, err := evalExec(t, env, `out = sys["exec_cmd"]("sleep 5", timeout=1)`)
	if err == nil {
		t.Fatal("expected exec_cmd to time out")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error = %v, want a timeout", err)
	}
}

// Output beyond the cap must fail closed (error), never silently truncate.
func TestExecCmdOutputCapFailsClosed(t *testing.T) {
	env := execEnv(t, allowAllEngine(t), false)
	_, err := evalExec(t, env, `out = sys["exec_cmd"]("head -c 5000 /dev/zero", max_output=1024, timeout=5)`)
	if err == nil {
		t.Fatal("expected exec_cmd to fail on output overrun")
	}
	if !strings.Contains(err.Error(), "output exceeded") {
		t.Fatalf("error = %v, want an output-cap failure", err)
	}
}

func TestExecJSONParses(t *testing.T) {
	env := execEnv(t, allowAllEngine(t), false)
	g, err := evalExec(t, env, `
v = sys["exec_json"]("echo '{\"a\": 1, \"b\": [2,3]}'")
a = v["a"]
`)
	if err != nil {
		t.Fatalf("exec_json: %v", err)
	}
	// JSON numbers decode to float64, so exec_json yields a Starlark float.
	if f, ok := starlark.AsFloat(g["a"]); !ok || f != 1 {
		t.Fatalf("a = %v, want 1", g["a"])
	}
}

func TestExecAsyncWaitAndOutput(t *testing.T) {
	env := execEnv(t, allowAllEngine(t), false)
	g, err := evalExec(t, env, `
job = sys["exec_async"]("echo async", timeout=5)
ok = job.wait()
out = job.output()
`)
	if err != nil {
		t.Fatalf("exec_async: %v", err)
	}
	if g["ok"] != starlark.Bool(true) {
		t.Fatalf("wait = %v, want True", g["ok"])
	}
	got, _ := starlark.AsString(g["out"])
	if strings.TrimSpace(got) != "async" {
		t.Fatalf("output = %q, want async", got)
	}
}

// A failed exec_cmd's error tail is printed to the terminal: colors, a window
// title and other control bytes are removed, the text is kept.
func TestExecCmdErrorTailHasNoTerminalControls(t *testing.T) {
	env := execEnv(t, allowAllEngine(t), false)
	_, err := evalExec(t, env, `sys.exec_cmd("printf '\\033[31mred\\033[0m \\033]0;owned\\007ok\\a\\r\\n'; exit 2")`)
	if err == nil {
		t.Fatal("exec_cmd of a failing command returned no error")
	}
	msg := err.Error()
	if strings.ContainsAny(msg, "\x1b\x07\r") || strings.Contains(msg, "owned") {
		t.Fatalf("error kept terminal controls: %q", msg)
	}
	if !strings.Contains(msg, "red ok") {
		t.Fatalf("error lost the output text: %q", msg)
	}
}

func TestStripTerminalControls(t *testing.T) {
	for in, want := range map[string]string{
		"plain\ttext\n":               "plain\ttext\n",
		"\x1b[1;31mbold\x1b[0m":       "bold",
		"\x1b]0;title\x1b\\after":     "after",
		"\x1b]8;;http://x\x07link":    "link",
		"a\x1b(Bb":                    "ab",
		"cut\x1b[31":                  "cut",
		"cut\x1b":                     "cut",
		"bell\a nul\x00 del\x7f done": "bell nul del done",
		"\u009b31mred\u009b0m":        "31mred0m",
		"\u009d0;x\u009c":             "0;x",
		"\x1b日x":                      "日x",
		"\x1b]0;t\x1b[31merror":       "error",
		"bad\xffbyte":                 "badbyte",
		"\x1b]0;t\nERR: denied":       "\nERR: denied",
		"\x1b[31\x1b[0mok":            "ok",
		"\x1b\x1b[31mx":               "x",
	} {
		if got := stripTerminalControls(in); got != want {
			t.Errorf("stripTerminalControls(%q) = %q, want %q", in, got, want)
		}
	}
}
