package starlarkext

import (
	"fmt"
	"os"
	"os/exec"
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
	fmt.Fprintf(&b, "%q,\n", touch)
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

// A Starlark custom command would run on a worker goroutine against the
// session's shared, unfrozen globals. The batch is refused before any command
// starts.
func TestParallelRefusesCustomCommandBeforeRun(t *testing.T) {
	env := execEnv(t, allowAllEngine(t), false)
	marker := markerPath(t)
	cases := []string{"bump", "true && bump x", "command bump", "eval 'bump'"}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			src := fmt.Sprintf(`
hits = []
def bump(argv):
    hits.append(1)
sys["register_command"]("bump", bump)
sys["parallel"]([%q, %q, "bump", "bump"], jobs=4, timeout=5)
`, "touch "+marker, cmd)
			g, err := evalExec(t, env, src)
			if err == nil || !strings.Contains(err.Error(), `sys.parallel cannot run Starlark custom command "bump"`) {
				t.Fatalf("error = %v", err)
			}
			if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
				t.Fatalf("a command ran before the refusal: %v", statErr)
			}
			if hits, ok := g["hits"].(*starlark.List); ok && hits.Len() != 0 {
				t.Fatalf("custom command ran %d times", hits.Len())
			}
		})
	}
}

// The worker's globals copy has no custom-command table, so a name that the
// pre-flight cannot see (built at run time) still cannot reach Starlark.
func TestParallelIsolatedDropsCustomCommands(t *testing.T) {
	commands := starlark.NewDict(1)
	if err := commands.SetKey(starlark.String("bump"), starlark.None); err != nil {
		t.Fatal(err)
	}
	p := execParams{session: &security.SessionState{SessionID: "s1", Globals: starlark.StringDict{
		"__custom_commands__": commands,
		"X":                   starlark.String("y"),
	}}}
	iso, err := p.isolated()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := iso.session.Globals["__custom_commands__"]; ok {
		t.Fatal("isolated globals still carry __custom_commands__")
	}
	if iso.session.Globals["X"] != starlark.String("y") || iso.session.SessionID != "s1" {
		t.Fatalf("isolated session lost state: %+v", iso.session)
	}
}

// A failure stops the batch: with jobs=1 the command after a failing one never
// starts.
func TestParallelFailureStopsLaterCommands(t *testing.T) {
	env := execEnv(t, allowAllEngine(t), false)
	marker := markerPath(t)
	src := fmt.Sprintf("sys[\"parallel\"]([\"false\", %q], jobs=1, timeout=5)\n", "touch "+marker)
	_, err := evalExec(t, env, src)
	if err == nil || !strings.Contains(err.Error(), "command 0") {
		t.Fatalf("error = %v", err)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("command after the failure ran: %v", statErr)
	}
}

// A failure cancels commands already running in other workers.
func TestParallelFailureCancelsRunning(t *testing.T) {
	env := execEnv(t, allowAllEngine(t), false)
	start := time.Now()
	_, err := evalExec(t, env, `sys["parallel"](["sleep 5", "false"], jobs=2, timeout=10)`)
	if err == nil || !strings.Contains(err.Error(), "command 1") {
		t.Fatalf("error = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("batch took %s after a failure, want the sleep canceled", elapsed)
	}
}

// Policy is checked for every command before any starts.
func TestParallelPreflightDenialRunsNothing(t *testing.T) {
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
	marker := markerPath(t)
	src := fmt.Sprintf("sys[\"parallel\"]([%q, \"sleep 0\", \"echo no\"], jobs=1, timeout=5)\n", "touch "+marker)
	_, err = evalExec(t, env, src)
	if err == nil || !strings.Contains(err.Error(), "command 2") || !strings.Contains(err.Error(), "echo denied") {
		t.Fatalf("error = %v", err)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("a command ran before the denial: %v", statErr)
	}
}

// Thread.Cancel from another goroutine stops a running batch.
func TestParallelThreadCancelStopsBatch(t *testing.T) {
	env := execEnv(t, allowAllEngine(t), false)
	thread := &starlark.Thread{Name: "cancel-test"}
	timer := time.AfterFunc(300*time.Millisecond, func() { thread.Cancel("operator interrupt") })
	defer timer.Stop()
	start := time.Now()
	_, err := starlark.ExecFile(thread, "t.star", `sys["parallel"](["sleep 5", "sleep 5"], jobs=2, timeout=10)`, env)
	if err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("error = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("canceled batch took %s", elapsed)
	}
}

// The overall deadline bounds the batch and is itself bounded.
func TestParallelDeadline(t *testing.T) {
	env := execEnv(t, allowAllEngine(t), false)
	start := time.Now()
	_, err := evalExec(t, env, `sys["parallel"](["sleep 5", "sleep 5", "sleep 5"], jobs=1, timeout=10, deadline=1)`)
	if err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("error = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("deadline batch took %s", elapsed)
	}
	for _, bad := range []string{"-1", "3601"} {
		_, err := evalExec(t, env, `sys["parallel"](["true"], deadline=`+bad+`)`)
		if err == nil || !strings.Contains(err.Error(), "deadline must be") {
			t.Fatalf("deadline=%s error = %v", bad, err)
		}
	}
}

// A deadline must kill the whole process group of a command. A shell that
// forks its children (Debian dash) leaves a grandchild that holds the output
// pipe and outlives the shell when only the shell is signaled. A background
// child of sh ignores SIGINT, so only a group SIGKILL ends it promptly.
func TestParallelDeadlineKillsProcessGroup(t *testing.T) {
	if _, err := exec.LookPath("pgrep"); err != nil {
		t.Skip("pgrep not available")
	}
	env := execEnv(t, allowAllEngine(t), false)
	marker := fmt.Sprintf("30.%d", 100000+time.Now().UnixNano()%800000)
	t.Cleanup(func() { _ = exec.Command("pkill", "-KILL", "-f", "sleep "+marker).Run() })
	start := time.Now()
	_, err := evalExec(t, env, `sys["parallel"](["sh -c 'sleep `+marker+` & sleep `+marker+`'"], timeout=60, deadline=1)`)
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("error = %v", err)
	}
	if elapsed > 1300*time.Millisecond {
		t.Fatalf("deadline batch took %s, want <= 1.3s", elapsed)
	}
	var left []byte
	for i := 0; i < 20; i++ {
		left, _ = exec.Command("pgrep", "-f", "sleep "+marker).Output()
		if len(strings.TrimSpace(string(left))) == 0 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("sleep children survived the deadline: pids %q", strings.TrimSpace(string(left)))
}

// Each worker gets its own __aliases__ and __shopts__ dicts: a worker's
// `alias` or `set -x` must not write the caller's dicts or a sibling's.
func TestParallelIsolatedCopiesAliasesAndShopts(t *testing.T) {
	aliases := starlark.NewDict(1)
	if err := aliases.SetKey(starlark.String("ll"), starlark.String("ls -l")); err != nil {
		t.Fatal(err)
	}
	shopts := starlark.NewDict(1)
	if err := shopts.SetKey(starlark.String("errexit"), starlark.True); err != nil {
		t.Fatal(err)
	}
	p := execParams{session: &security.SessionState{Globals: starlark.StringDict{
		"__aliases__": aliases,
		"__shopts__":  shopts,
	}}}
	a, err := p.isolated()
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.isolated()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"__aliases__", "__shopts__"} {
		da, okA := a.session.Globals[name].(*starlark.Dict)
		db, okB := b.session.Globals[name].(*starlark.Dict)
		if !okA || !okB {
			t.Fatalf("%s is not a dict in the isolated copy", name)
		}
		src := p.session.Globals[name].(*starlark.Dict)
		if da == src || db == src || da == db {
			t.Fatalf("%s is shared between the caller and workers", name)
		}
		if da.Len() != src.Len() {
			t.Fatalf("%s copy has %d entries, want %d", name, da.Len(), src.Len())
		}
	}
	if err := a.session.Globals["__aliases__"].(*starlark.Dict).SetKey(starlark.String("x"), starlark.String("y")); err != nil {
		t.Fatal(err)
	}
	if aliases.Len() != 1 {
		t.Fatalf("worker alias leaked into the caller: %v", aliases)
	}
}

// End to end under -race: concurrent `alias` and `set -x` in workers must not
// race on, or write, the caller's dicts.
func TestParallelAliasAndShoptDoNotLeak(t *testing.T) {
	env := execEnv(t, allowAllEngine(t), false)
	aliases := starlark.NewDict(1)
	shopts := starlark.NewDict(1)
	env["__aliases__"] = aliases
	env["__shopts__"] = shopts
	cmds := make([]string, 0, 8)
	for i := 0; i < 4; i++ {
		cmds = append(cmds, fmt.Sprintf(`"alias a%d=echo"`, i), `"set -x"`)
	}
	_, err := evalExec(t, env, `out = sys["parallel"]([`+strings.Join(cmds, ",")+`], jobs=8, timeout=10)`)
	if err != nil {
		t.Fatalf("parallel: %v", err)
	}
	if aliases.Len() != 0 {
		t.Fatalf("worker aliases leaked into the caller: %v", aliases)
	}
	if shopts.Len() != 0 {
		t.Fatalf("worker shopts leaked into the caller: %v", shopts)
	}
}

// SIGINT in the REPL calls thread.Cancel. A running batch must return soon
// after, with its child processes killed rather than left to finish.
func TestParallelThreadCancelKillsChildrenPromptly(t *testing.T) {
	env := execEnv(t, allowAllEngine(t), false)
	thread := &starlark.Thread{Name: "cancel-kill-test"}
	const marker = "sleep 5.4321"
	canceled := make(chan time.Time, 1)
	timer := time.AfterFunc(200*time.Millisecond, func() {
		canceled <- time.Now()
		thread.Cancel("interrupted")
	})
	defer timer.Stop()
	start := time.Now()
	_, err := starlark.ExecFile(thread, "t.star", `sys["parallel"](["`+marker+`"] * 2, jobs=2, timeout=10)`, env)
	returned := time.Now()
	if err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("error = %v", err)
	}
	cancelAt := <-canceled
	if lag := returned.Sub(cancelAt); lag > 500*time.Millisecond {
		t.Fatalf("returned %s after Cancel (total %s), want under 500ms", lag, returned.Sub(start))
	}
	t.Logf("returned %s after Cancel, total %s", returned.Sub(cancelAt), returned.Sub(start))
	time.Sleep(100 * time.Millisecond)
	out, _ := exec.Command("pgrep", "-f", marker).Output()
	if pids := strings.TrimSpace(string(out)); pids != "" {
		t.Fatalf("child processes still running after cancel: %s", pids)
	}
}
