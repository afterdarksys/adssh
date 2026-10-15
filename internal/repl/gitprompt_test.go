package repl

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFormatGitStatus(t *testing.T) {
	cases := []struct {
		name string
		out  string
		cut  bool
		want string
	}{
		{name: "clean", out: "## main\n", want: "main"},
		{name: "tracking", out: "## main...origin/main\n", want: "main"},
		{name: "ahead", out: "## main...origin/main [ahead 1]\n", want: "main"},
		{name: "dirty", out: "## main\n M file\n", want: "main*"},
		{name: "detached", out: "## HEAD (no branch)\n", want: "HEAD"},
		{name: "no commits", out: "## No commits yet on main\n", want: "main"},
		{name: "not a repo", out: "fatal: not a git repository\n", want: ""},
		{name: "controls", out: "## \x1b[31mmain\n", want: "[31mmain"},
		{name: "truncated", out: "## main\n", cut: true, want: "main*"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatGitStatus(tc.out, tc.cut); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestExpandPromptGitOffDoesNotLookup(t *testing.T) {
	calls := 0
	cache := &gitPromptCache{
		enabled: false,
		cwd:     "/tmp",
		lookup: func(cwd string) string {
			calls++
			return "main*"
		},
	}
	got := expandPrompt(`\w \g`, nil, nil, "/work", cache)
	if calls != 0 {
		t.Fatalf("lookup calls %d", calls)
	}
	if strings.Contains(got, "main") || strings.Contains(got, "*") {
		t.Fatalf("segment leaked: %q", got)
	}
	if !strings.Contains(got, "/work") && !strings.HasSuffix(got, " ") {
		t.Fatalf("prompt %q", got)
	}
}

func TestExpandPromptGitCachesOneLookup(t *testing.T) {
	calls := 0
	cache := &gitPromptCache{
		enabled: true,
		cwd:     "/repo",
		lookup: func(cwd string) string {
			calls++
			if cwd != "/repo" {
				t.Fatalf("cwd %s", cwd)
			}
			return "main*"
		},
	}
	a := expandPrompt(`\g`, nil, nil, "/repo", cache)
	b := expandPrompt(`\g`, nil, nil, "/repo", cache)
	if calls != 1 {
		t.Fatalf("calls %d", calls)
	}
	if a != "main*" || b != "main*" {
		t.Fatalf("a %q b %q", a, b)
	}
}

func TestApplyGitPrompt(t *testing.T) {
	next, handled, err := applyGitPrompt("set -e", false)
	if handled || err != nil || next {
		t.Fatalf("set -e handled next %v err %v", next, err)
	}
	next, handled, err = applyGitPrompt("set gitprompt", false)
	if !handled || err != nil || next {
		t.Fatalf("query next %v err %v", next, err)
	}
	next, handled, err = applyGitPrompt("set gitprompt on", false)
	if !handled || err != nil || !next {
		t.Fatalf("on next %v err %v", next, err)
	}
	next, handled, err = applyGitPrompt("set gitprompt off", true)
	if !handled || err != nil || next {
		t.Fatalf("off next %v err %v", next, err)
	}
	next, handled, err = applyGitPrompt("set gitprompt maybe", false)
	if !handled || err == nil || next {
		t.Fatalf("bad value next %v err %v", next, err)
	}
}

func TestGitPromptFromEnv(t *testing.T) {
	for _, v := range []string{"", "0", "false", "no", "off", "maybe"} {
		if gitPromptFromEnv(v) {
			t.Fatalf("%q enabled", v)
		}
	}
	for _, v := range []string{"1", "true", "YES", "on"} {
		if !gitPromptFromEnv(v) {
			t.Fatalf("%q disabled", v)
		}
	}
}

func TestGitPromptSegmentRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=adssh",
			"GIT_AUTHOR_EMAIL=adssh@example.com",
			"GIT_COMMITTER_NAME=adssh",
			"GIT_COMMITTER_EMAIL=adssh@example.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-b", "main")
	if got := gitPromptSegment(dir); got != "main" {
		t.Fatalf("clean %q", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := gitPromptSegment(dir); got != "main*" {
		t.Fatalf("dirty %q", got)
	}
	if got := gitPromptSegment(t.TempDir()); got != "" {
		t.Fatalf("non-repo %q", got)
	}
}

func TestGitPromptSegmentTimeout(t *testing.T) {
	bin := t.TempDir()
	script := filepath.Join(bin, "git")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 5\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	start := time.Now()
	if got := gitPromptSegment(t.TempDir()); got != "" {
		t.Fatalf("slow git returned %q", got)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("timeout took %s", time.Since(start))
	}
}
