package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestOpenReadsARegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, info, err := Open(nil, path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	body, err := ReadAll(f, info, 5)
	if err != nil || string(body) != "hello" {
		t.Fatalf("body = %q, err = %v", body, err)
	}
}

func TestOpenRelativeToDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	f, info, err := Open(d, "f")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if info.Size() != 1 {
		t.Fatalf("size = %d", info.Size())
	}
}

func TestOpenRejectsSymlinkDirectoryFifoAndMissing(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(nil, link); !errors.Is(err, ErrSymlink) {
		t.Fatalf("symlink: %v", err)
	}
	if _, _, err := Open(nil, dir); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("directory: %v", err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(nil, fifo); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("fifo: %v", err)
	}
	if _, _, err := Open(nil, filepath.Join(dir, "missing")); !os.IsNotExist(err) {
		t.Fatalf("missing: %v", err)
	}
}

func TestReadAllRejectsOversized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 11)), 0o600); err != nil {
		t.Fatal(err)
	}
	f, info, err := Open(nil, path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := ReadAll(f, info, 10); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized: %v", err)
	}
}
