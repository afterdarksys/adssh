package repl

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chzyer/readline"
	"github.com/creack/pty"
	"go.starlark.net/starlark"
)

func TestListenerTypingNeverInsertsSuggestion(t *testing.T) {
	hist := []string{"echo hello"}
	l := newAdsshListener(&hist)
	for _, tc := range []struct {
		line string
		key  rune
	}{
		{"e", 'e'},
		{"echo hel", 'l'},
		{"echo help", 'p'},
		{"echo hel", readline.CharBackspace},
	} {
		if got, _, ok := l.OnChange([]rune(tc.line), len([]rune(tc.line)), tc.key); ok {
			t.Fatalf("OnChange(%q, %q) changed the line to %q", tc.line, tc.key, string(got))
		}
	}
}

func TestListenerForwardAtEndAcceptsSuggestion(t *testing.T) {
	hist := []string{"echo hello", "ls -la"}
	l := newAdsshListener(&hist)
	got, pos, ok := l.OnChange([]rune("echo h"), 6, readline.CharForward)
	if !ok || string(got) != "echo hello" || pos != len("echo hello") {
		t.Fatalf("got %q pos %d ok %v, want \"echo hello\" at its end", string(got), pos, ok)
	}
	if _, _, ok := l.OnChange([]rune("echo h"), 3, readline.CharForward); ok {
		t.Fatal("→ before the end of the line accepted a suggestion")
	}
	if _, _, ok := l.OnChange([]rune("cat"), 3, readline.CharForward); ok {
		t.Fatal("→ with no matching history changed the line")
	}
}

func TestHistorySuggestionSkipsControlCharacters(t *testing.T) {
	hist := []string{"echo safe", "echo \x1b]0;pwned\x07", "echo \u009b2J"}
	if got := historySuggestion(hist, "echo "); got != "safe" {
		t.Fatalf("got %q, want the newest entry without control characters", got)
	}
	if got := historySuggestion([]string{"echo \x1b[2J"}, "echo "); got != "" {
		t.Fatalf("got %q, want no suggestion from an entry with an escape", got)
	}
	if got := historySuggestion(hist, ""); got != "" {
		t.Fatalf("empty line got suggestion %q", got)
	}
}

func TestSuggestionPainterDrawsWithoutTouchingLine(t *testing.T) {
	hist := []string{"echo hello"}
	p := &suggestionPainter{history: &hist, width: func() int { return 80 }, prompt: "adssh> "}
	line := []rune("echo h")
	got := string(p.Paint(line, len(line)))
	want := "echo h" + ansiDim + "ello" + ansiReset + "\x1b[4D"
	if got != want {
		t.Fatalf("Paint = %q, want %q", got, want)
	}
	if string(line) != "echo h" {
		t.Fatalf("Paint changed the line to %q", string(line))
	}
	if got := string(p.Paint(line, 2)); got != "echo h" {
		t.Fatalf("cursor mid-line: Paint = %q, want no suggestion", got)
	}
}

func TestSuggestionPainterStaysOnTheRow(t *testing.T) {
	hist := []string{"echo hello world"}
	// 7 prompt + 6 line + 1 free column leaves 6 columns of a 20-column row.
	p := &suggestionPainter{history: &hist, width: func() int { return 20 }, prompt: "\x1b[1madssh>\x1b[0m "}
	line := []rune("echo h")
	got := string(p.Paint(line, len(line)))
	want := "echo h" + ansiDim + "ello w" + ansiReset + "\x1b[6D"
	if got != want {
		t.Fatalf("Paint = %q, want %q", got, want)
	}
	p.width = func() int { return 14 }
	if got := string(p.Paint(line, len(line))); got != "echo h" {
		t.Fatalf("full row: Paint = %q, want no suggestion", got)
	}
}

// The REPL runs in a child whose fd 0/1/2 are a pty, as an SSH session child
// does. With "echo hello" in history, typing "echo help" must run exactly
// that. The old listener put the suggestion in the line, so it ran
// "echo helplo".
func TestPTYTypedLineRunsWithoutSuggestion(t *testing.T) {
	if os.Getenv("ADSSH_TEST_SUGGEST_CHILD") == "1" {
		Start(starlark.StringDict{}, false, filepath.Join(os.Getenv("HOME"), "history"), os.Stdin, os.Stdout, os.Stderr)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestPTYTypedLineRunsWithoutSuggestion$", "-test.count=1")
	cmd.Env = append(os.Environ(), "ADSSH_TEST_SUGGEST_CHILD=1", "HOME="+t.TempDir(), "TERM=xterm-256color")
	master, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 30, Cols: 100})
	if err != nil {
		t.Skipf("pty unavailable: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	out := make(chan string, 1)
	var seen atomic.Value
	seen.Store("")
	go func() {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			b.Write(buf[:n])
			seen.Store(b.String())
			if err != nil {
				out <- b.String()
				return
			}
		}
	}()
	waitFor := func(d time.Duration) { time.Sleep(d) }
	// Type only after the first prompt, so raw mode is on.
	for deadline := time.Now().Add(10 * time.Second); !strings.Contains(seen.Load().(string), "adssh> "); {
		if time.Now().After(deadline) {
			t.Fatal("no prompt")
		}
		waitFor(50 * time.Millisecond)
	}
	// "echo hel" shows the dim suggestion "lo"; "p" must not take it. Then
	// "echo h" plus → accepts the newest match, "echo help".
	for _, s := range []string{"echo hello\r", "echo hel", "p", "\r", "echo h", "\x1b[C", "\r", "exit\r"} {
		for _, c := range s {
			_, _ = master.Write([]byte(string(c)))
			waitFor(40 * time.Millisecond)
		}
		waitFor(400 * time.Millisecond)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("REPL did not exit")
	}
	_ = master.Close()
	got := <-out
	if strings.Contains(got, "helplo") {
		t.Fatalf("the suggestion ran as part of the line:\n%q", got)
	}
	if !strings.Contains(got, ansiDim+"lo"+ansiReset) {
		t.Fatalf("the suggestion was never drawn:\n%q", got)
	}
	if strings.Count(got, "\r\nhelp\r\n") != 2 {
		t.Fatalf("want help printed twice (typed, then accepted with →):\n%q", got)
	}
}
