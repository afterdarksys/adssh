package starlarkext

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
)

func TestParallelOrderedOutput(t *testing.T) {
	env := execEnv(t, allowAllEngine(t), false)
	g, err := evalExec(t, env, `
out = sys["parallel"](["echo a", "echo b", "echo c"], jobs=3, timeout=10)
`)
	if err != nil {
		t.Fatalf("parallel: %v", err)
	}
	list, ok := g["out"].(*starlark.List)
	if !ok || list.Len() != 3 {
		t.Fatalf("out = %v", g["out"])
	}
	want := []string{"a", "b", "c"}
	for i, w := range want {
		got, _ := starlark.AsString(list.Index(i))
		if strings.TrimSpace(got) != w {
			t.Fatalf("out[%d] = %q, want %s", i, got, w)
		}
	}
}

func TestParallelOverlapsJobs(t *testing.T) {
	env := execEnv(t, allowAllEngine(t), false)
	start := time.Now()
	_, err := evalExec(t, env, `
sys["parallel"](["sleep 1", "sleep 1", "sleep 1"], jobs=3, timeout=10)
`)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("parallel: %v", err)
	}
	if elapsed > 2500*time.Millisecond {
		t.Fatalf("3 jobs took %s, want overlap under 2.5s", elapsed)
	}

	start = time.Now()
	_, err = evalExec(t, env, `
sys["parallel"](["sleep 1", "sleep 1", "sleep 1"], jobs=1, timeout=10)
`)
	elapsed = time.Since(start)
	if err != nil {
		t.Fatalf("serial parallel: %v", err)
	}
	if elapsed < 2800*time.Millisecond {
		t.Fatalf("jobs=1 took %s, want at least 2.8s", elapsed)
	}
}

func TestParallelDeniedCommandFailsClosed(t *testing.T) {
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
	_, err = evalExec(t, env, `sys["parallel"](["true", "echo no"], timeout=5)`)
	if err == nil {
		t.Fatal("expected a denied command to fail the call")
	}
	if !strings.Contains(err.Error(), "command 1") || !strings.Contains(err.Error(), "echo denied") {
		t.Fatalf("error = %v", err)
	}
}

func TestParallelBuiltinDeniedRunsNothing(t *testing.T) {
	eng, err := security.NewEngine(security.EngineConfig{PolicySource: []byte(`
package adssh.authz
default allow = false
allow { input.command != "starlark.sys.parallel" }
deny_reason = "parallel denied" { input.command == "starlark.sys.parallel" }
`)})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	env := execEnv(t, eng, false)
	marker := markerPath(t)
	src := fmt.Sprintf("sys[\"parallel\"]([\"touch %s\"])\n", marker)
	_, err = evalExec(t, env, src)
	if err == nil || !strings.Contains(err.Error(), "parallel denied") {
		t.Fatalf("error = %v", err)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("marker created despite builtin denial: %v", statErr)
	}
}

func TestParallelNonZeroFailsClosed(t *testing.T) {
	env := execEnv(t, allowAllEngine(t), false)
	_, err := evalExec(t, env, `sys["parallel"](["echo a", "false", "echo c"], timeout=5)`)
	if err == nil || !strings.Contains(err.Error(), "command 1") {
		t.Fatalf("error = %v", err)
	}
}

func TestParallelTimeoutFailsClosed(t *testing.T) {
	env := execEnv(t, allowAllEngine(t), false)
	_, err := evalExec(t, env, `sys["parallel"](["sleep 5"], timeout=1)`)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error = %v", err)
	}
}

func TestParallelOutputCapFailsClosed(t *testing.T) {
	env := execEnv(t, allowAllEngine(t), false)
	_, err := evalExec(t, env, `sys["parallel"](["head -c 2000000 /dev/zero"], max_output=10485760, timeout=5)`)
	if err == nil || !strings.Contains(err.Error(), "output exceeded") {
		t.Fatalf("error = %v", err)
	}
}

func TestParallelRejectsBadInputBeforeRun(t *testing.T) {
	env := execEnv(t, allowAllEngine(t), false)
	marker := markerPath(t)
	touch := fmt.Sprintf("touch %s", marker)

	cases := []struct {
		name string
		src  string
		want string
	}{
		{name: "empty", src: `sys["parallel"]([])`, want: "no commands"},
		{name: "blank", src: `sys["parallel"](["   "])`, want: "empty"},
		{name: "type", src: fmt.Sprintf("sys[\"parallel\"]([%q, 1])\n", touch), want: "want a string"},
		{name: "parse", src: fmt.Sprintf("sys[\"parallel\"]([%q, \"echo $(\"])\n", touch), want: "parse error"},
		{name: "jobs", src: fmt.Sprintf("sys[\"parallel\"]([%q], jobs=65)\n", touch), want: "jobs must be"},
		{name: "negative jobs", src: fmt.Sprintf("sys[\"parallel\"]([%q], jobs=-1)\n", touch), want: "jobs must be"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := evalExec(t, env, tc.src)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
				t.Fatalf("command ran: %v", statErr)
			}
		})
	}

	var b strings.Builder
	b.WriteString("sys[\"parallel\"]([\n")
	b.WriteString(fmt.Sprintf("%q,\n", touch))
	for i := 0; i < maxParallelCommands; i++ {
		b.WriteString("\"true\",\n")
	}
	b.WriteString("])\n")
	_, err := evalExec(t, env, b.String())
	if err == nil || !strings.Contains(err.Error(), "exceeds the limit") {
		t.Fatalf("count error = %v", err)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("command ran after count rejection: %v", statErr)
	}

	_, err = evalExec(t, env, `sys["parallel"](["echo " + ("a" * 20000)])`)
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("size error = %v", err)
	}
}

func TestParallelAbsentWhenRestricted(t *testing.T) {
	globals := starlark.StringDict{}
	SetupExtensions(ExtensionOptions{Env: globals, Restricted: true})
	sysValue, ok := globals["sys"].(*starlark.Dict)
	if !ok {
		t.Fatalf("sys is %T", globals["sys"])
	}
	if value, found, err := sysValue.Get(starlark.String("parallel")); err != nil || found {
		t.Fatalf("restricted sys.parallel = (%v, %v, %v), want absent", value, found, err)
	}
}

func markerPath(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "ran")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	return path
}
