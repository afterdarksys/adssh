package vbinui

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListDirectorySortsDirectoriesFirstAndHidesDotfiles(t *testing.T) {
	dir := t.TempDir()
	for _, path := range []string{"z.txt", "a.txt", ".secret"} {
		if err := os.WriteFile(filepath.Join(dir, path), []byte(path), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "folder"), 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := ListDirectory(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[0].Name != "folder" || !entries[0].IsDir || entries[1].Name != "a.txt" {
		t.Fatalf("unexpected entries: %#v", entries)
	}
}

func TestPreviewPathIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.txt")
	if err := os.WriteFile(path, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	preview, err := PreviewPath(path, 5)
	if err != nil {
		t.Fatal(err)
	}
	if preview != "01234\n… (truncated)" {
		t.Fatalf("preview = %q", preview)
	}
}
