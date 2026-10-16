package repl

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func denyCommands(names ...string) denyFunc {
	return func(args []string) bool {
		for _, n := range names {
			if args[0] == n {
				return true
			}
		}
		return false
	}
}

func TestClassifyHighlight(t *testing.T) {
	deny := denyCommands("shutdown", "curl")
	cases := []struct {
		line string
		want highlightLevel
	}{
		{"ls -la", highlightNone},
		{"", highlightNone},
		{"shutdown -h now", highlightDenied},
		{"rm -rf /tmp/x", highlightDestructive},
		{"echo hi | curl -d @- example.com", highlightDenied},
		{"echo $(shutdown now)", highlightDenied},
		{"!shutdown", highlightDenied},
		{"$ shutdown", highlightDenied},
		{"git push --force", highlightDestructive},
		{"aws.ec2.terminate(ids=['i-1'])", highlightDestructive},
		// A Starlark line never goes to the shell policy check.
		{"shutdown = 1", highlightNone},
		// Incomplete shell still gets the destructive check.
		{"rm -rf 'unterminated", highlightDestructive},
		// Ghost-suggestion escapes from the listener are ignored.
		{"ls\x1b[2m -la\x1b[0m", highlightNone},
	}
	for _, c := range cases {
		if got := classifyHighlight(c.line, deny); got != c.want {
			t.Errorf("classifyHighlight(%q) = %v, want %v", c.line, got, c.want)
		}
	}
	// Denial wins over destructive.
	if got := classifyHighlight("rm -rf /", denyCommands("rm")); got != highlightDenied {
		t.Errorf("denied destructive = %v", got)
	}
	// No policy function: only the destructive check.
	if got := classifyHighlight("shutdown", nil); got != highlightNone {
		t.Errorf("nil deny = %v", got)
	}
}

// Only literal words reach the policy check; nothing is expanded.
func TestHighlightLiteralCommands(t *testing.T) {
	var seen [][]string
	record := func(args []string) bool {
		seen = append(seen, append([]string(nil), args...))
		return false
	}
	classifyHighlight("ls -la $HOME; $CMD x; cat 'a b'", record)
	got := make([]string, len(seen))
	for i, a := range seen {
		got[i] = strings.Join(a, "|")
	}
	want := []string{"ls|-la", "cat"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("policy saw %q, want %q", got, want)
	}
}

func TestHighlightColor(t *testing.T) {
	if highlightColor(highlightNone) != "" {
		t.Error("none must not color")
	}
	if highlightColor(highlightDenied) != "\x1b[31m" {
		t.Error("denied must be red")
	}
	if highlightColor(highlightDestructive) != "\x1b[33m" {
		t.Error("destructive must be yellow")
	}
}

func TestHighlightPermitted(t *testing.T) {
	if highlightPermitted(false) {
		t.Error("highlight permitted without a terminal")
	}
	if !highlightPermitted(true) {
		t.Error("highlight refused on a terminal")
	}
	if highlightInitial("1", false) {
		t.Error("ADSSH_HIGHLIGHT turned it on without a terminal")
	}
	if !highlightInitial("1", true) || highlightInitial("", true) {
		t.Error("ADSSH_HIGHLIGHT parse")
	}
}

func TestHandleHighlightLine(t *testing.T) {
	var out, errOut bytes.Buffer
	allow := func([]string) error { return nil }
	deny := func([]string) error { return errors.New("denied") }

	if _, handled := handleHighlightLine("set -x", false, true, allow, &out, &errOut); handled {
		t.Fatal("handled an unrelated set line")
	}
	if next, handled := handleHighlightLine("set highlight on", false, true, allow, &out, &errOut); !handled || !next {
		t.Fatalf("on: next=%v handled=%v", next, handled)
	}
	if next, _ := handleHighlightLine("set highlight off", true, true, allow, &out, &errOut); next {
		t.Fatal("off left it on")
	}
	if next, _ := handleHighlightLine("set highlight on", false, false, allow, &out, &errOut); next {
		t.Fatal("turned on without a terminal")
	}
	errOut.Reset()
	if next, _ := handleHighlightLine("set highlight on", false, true, deny, &out, &errOut); next {
		t.Fatal("turned on although the gate denied it")
	}
	if !strings.Contains(errOut.String(), "denied") {
		t.Fatalf("gate denial not reported: %q", errOut.String())
	}
	if next, _ := handleHighlightLine("set highlight maybe", true, true, allow, &out, &errOut); !next {
		t.Fatal("bad value changed the state")
	}
}

// Smoke test of the editor hook: Paint never waits on the policy, the decision
// is debounced, and the line is colored once the decision lands.
func TestHighlighterPaintDebounced(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	refreshed := make(chan struct{}, 4)
	h := &highlighter{
		debounce: 20 * time.Millisecond,
		denied: func(args []string) bool {
			calls.Add(1)
			<-release
			return args[0] == "shutdown"
		},
		refresh: func() { refreshed <- struct{}{} },
	}

	// Off: the line is returned unchanged and nothing is evaluated.
	if got := string(h.Paint([]rune("shutdown"), 8)); got != "shutdown" {
		t.Fatalf("disabled paint = %q", got)
	}
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("disabled highlighter evaluated policy")
	}

	h.enabled.Store(true)
	for _, partial := range []string{"s", "sh", "shu", "shutdown"} {
		start := time.Now()
		if got := string(h.Paint([]rune(partial), len(partial))); got != partial {
			t.Fatalf("undecided paint = %q", got)
		}
		if time.Since(start) > 10*time.Millisecond {
			t.Fatal("Paint blocked")
		}
	}
	// Policy is still blocked: Paint must still return at once.
	time.Sleep(60 * time.Millisecond)
	start := time.Now()
	h.Paint([]rune("shutdown"), 8)
	if time.Since(start) > 10*time.Millisecond {
		t.Fatal("Paint blocked on a pending policy decision")
	}
	close(release)
	select {
	case <-refreshed:
	case <-time.After(2 * time.Second):
		t.Fatal("no refresh after the decision")
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("policy evaluated %d times for one debounced line, want 1", n)
	}
	if got := string(h.Paint([]rune("shutdown"), 8)); got != "\x1b[31mshutdown\x1b[0m" {
		t.Fatalf("decided paint = %q", got)
	}
	// An edit drops the color until the new line is decided.
	if got := string(h.Paint([]rune("shutdow"), 7)); got != "shutdow" {
		t.Fatalf("edited paint = %q", got)
	}
}

func TestHighlighterConcurrentPaint(t *testing.T) {
	h := &highlighter{debounce: time.Millisecond, denied: denyCommands("x")}
	h.enabled.Store(true)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				h.Paint([]rune(strings.Repeat("x", 1+(i+j)%3)), 1)
			}
		}(i)
	}
	wg.Wait()
}
