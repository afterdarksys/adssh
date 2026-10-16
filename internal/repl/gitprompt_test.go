package repl

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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

func writeHead(t *testing.T, gitDir, head string) {
	t.Helper()
	if err := os.MkdirAll(gitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte(head), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestGitPromptSegmentBranchFromHead(t *testing.T) {
	repo := t.TempDir()
	writeHead(t, filepath.Join(repo, ".git"), "ref: refs/heads/main\n")
	if got := gitPromptSegment(repo); got != "main" {
		t.Fatalf("branch %q", got)
	}
	sub := filepath.Join(repo, "a", "b")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := gitPromptSegment(sub); got != "main" {
		t.Fatalf("subdir %q", got)
	}
	if got := gitPromptSegment(t.TempDir()); got != "" {
		t.Fatalf("non-repo %q", got)
	}
	writeHead(t, filepath.Join(repo, ".git"), "ref: refs/heads/feature/x\n")
	if got := gitPromptSegment(repo); got != "feature/x" {
		t.Fatalf("slash branch %q", got)
	}
}

func TestGitPromptSegmentDetachedHead(t *testing.T) {
	repo := t.TempDir()
	writeHead(t, filepath.Join(repo, ".git"), "0123456789abcdef0123456789abcdef01234567\n")
	if got := gitPromptSegment(repo); got != "0123456" {
		t.Fatalf("detached %q", got)
	}
	writeHead(t, filepath.Join(repo, ".git"), "not a ref\n")
	if got := gitPromptSegment(repo); got != "" {
		t.Fatalf("garbage %q", got)
	}
}

func TestGitPromptSegmentGitdirFile(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "main", ".git", "worktrees", "wt")
	writeHead(t, real, "ref: refs/heads/wt-branch\n")
	wt := filepath.Join(root, "main", "wt")
	if err := os.MkdirAll(wt, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: ../.git/worktrees/wt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := gitPromptSegment(wt); got != "wt-branch" {
		t.Fatalf("relative gitdir %q", got)
	}
	t.Setenv("HOME", root)
	if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: "+real+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := gitPromptSegment(wt); got != "wt-branch" {
		t.Fatalf("absolute gitdir under home %q", got)
	}
}

func TestGitPromptSegmentGitdirEscapeRefused(t *testing.T) {
	root := t.TempDir()
	writeHead(t, filepath.Join(root, "elsewhere"), "ref: refs/heads/leak\n")
	wt := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(wt, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: ../../elsewhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := gitPromptSegment(wt); got != "" {
		t.Fatalf("two-level escape followed: %q", got)
	}
	t.Setenv("HOME", filepath.Join(root, "home"))
	if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: /etc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := gitPromptSegment(wt); got != "" {
		t.Fatalf("absolute gitdir outside home and cwd followed: %q", got)
	}
	// A gitdir that is itself a .git file is not followed a second time.
	chain := filepath.Join(root, "a", "chain")
	if err := os.MkdirAll(chain, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(chain, "HEAD"), []byte("gitdir: ../../elsewhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: ../chain\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := gitPromptSegment(wt); got != "" {
		t.Fatalf("chained gitdir %q", got)
	}
}

func TestGitPromptSegmentFIFOHeadDoesNotBlock(t *testing.T) {
	repo := t.TempDir()
	gitDir := filepath.Join(repo, ".git")
	if err := os.MkdirAll(gitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("mkfifo", filepath.Join(gitDir, "HEAD")).Run(); err != nil {
		t.Skip("mkfifo unavailable")
	}
	done := make(chan string, 1)
	go func() { done <- gitPromptSegment(repo) }()
	select {
	case got := <-done:
		if got != "" {
			t.Fatalf("fifo HEAD %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a FIFO HEAD blocked the prompt")
	}
}

func TestGitPromptSanitisesBranchName(t *testing.T) {
	repo := t.TempDir()
	hostile := "ref: refs/heads/ma\u202ein\x1b[31m\u0085x\u200by\u2066z\x7f\n"
	writeHead(t, filepath.Join(repo, ".git"), hostile)
	got := gitPromptSegment(repo)
	if got != "main[31mxyz" {
		t.Fatalf("sanitised %q", got)
	}
	long := "ref: refs/heads/" + strings.Repeat("\u00e9", 100) + "\n"
	writeHead(t, filepath.Join(repo, ".git"), long)
	if got := gitPromptSegment(repo); len([]rune(got)) != gitPromptMaxName {
		t.Fatalf("cap %d", len([]rune(got)))
	}
}

func TestGitPromptNeverRunsRepoHooks(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repo := t.TempDir()
	marker := filepath.Join(t.TempDir(), "ran")
	hook := filepath.Join(t.TempDir(), "fsmonitor.sh")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"config", "core.fsmonitor", hook},
		{"config", "filter.evil.clean", hook},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, ".gitattributes"), []byte("* filter=evil\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Dir(hook)+string(os.PathListSeparator)+os.Getenv("PATH"))
	got := gitPromptSegment(repo)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the git prompt ran a repository hook")
	}
	if got != "main" {
		t.Fatalf("branch %q", got)
	}
}

func TestGitPromptToggleRefusedInRestrictedAndSSH(t *testing.T) {
	for _, tc := range []struct {
		name       string
		restricted bool
		ssh        bool
	}{
		{"restricted", true, false},
		{"ssh child", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			allowed := gitPromptPermitted(tc.restricted, tc.ssh)
			if allowed {
				t.Fatal("git prompt permitted")
			}
			next, handled := handleGitPromptLine("set gitprompt on", false, allowed, &out, &errOut)
			if !handled || next {
				t.Fatalf("handled %v next %v", handled, next)
			}
			if !strings.Contains(errOut.String(), "not available") {
				t.Fatalf("stderr %q", errOut.String())
			}
			if gitPromptInitial("1", allowed) {
				t.Fatal("ADSSH_GIT_PROMPT enabled the prompt")
			}
		})
	}
	var out, errOut bytes.Buffer
	allowed := gitPromptPermitted(false, false)
	next, handled := handleGitPromptLine("set gitprompt on", false, allowed, &out, &errOut)
	if !allowed || !handled || !next || out.String() != "gitprompt on\n" {
		t.Fatalf("local toggle: allowed %v next %v out %q err %q", allowed, next, out.String(), errOut.String())
	}
	if !gitPromptInitial("1", allowed) {
		t.Fatal("ADSSH_GIT_PROMPT ignored in a local session")
	}
}
