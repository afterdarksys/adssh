package repl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareHistoryFileCreatesPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "history")
	if err := prepareHistoryFile(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("mode %v, err %v; want 0600", fi.Mode().Perm(), err)
	}
}

func TestPrepareHistoryFileTightensExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history")
	if err := os.WriteFile(path, []byte("ls\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := prepareHistoryFile(path); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0600 {
		t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(path); string(b) != "ls\n" {
		t.Fatalf("history content changed: %q", b)
	}
}

// A planted symlink (the old shared /tmp/.adssh_history case) is refused and
// its target is not created, written, or chmodded.
func TestPrepareHistoryFileRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "victim")
	if err := os.WriteFile(target, []byte("secret\n"), 0640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "history")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := prepareHistoryFile(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("got %v, want a symlink refusal", err)
	}
	fi, _ := os.Stat(target)
	if fi.Mode().Perm() != 0640 {
		t.Fatalf("symlink target mode changed to %v", fi.Mode().Perm())
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "created-through-link"), dangling); err != nil {
		t.Fatal(err)
	}
	if err := prepareHistoryFile(dangling); err == nil {
		t.Fatal("a dangling symlink was accepted")
	}
	if _, err := os.Lstat(filepath.Join(dir, "created-through-link")); err == nil {
		t.Fatal("a file was created through a dangling symlink")
	}
}

func TestPrepareHistoryFileRefusesNonRegular(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := prepareHistoryFile(dir); err == nil {
		t.Fatal("a directory was accepted as the history file")
	}
	if err := prepareHistoryFile(""); err != nil {
		t.Fatalf("empty path (history off): %v", err)
	}
}

func TestPrepareHistoryFileRefusesHardLink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history")
	if err := os.WriteFile(path, []byte("ls\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, filepath.Join(dir, "other-link")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if err := prepareHistoryFile(path); err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Fatalf("got %v, want a hard-link refusal", err)
	}
}
