package config

import (
	"os"
	"path/filepath"
	"testing"

	"go.starlark.net/starlark"
)

func TestLoadProfilesReturnsExecutionError(t *testing.T) {
	rcPath := filepath.Join(t.TempDir(), ".adsshrc")
	if err := os.WriteFile(rcPath, []byte("this is not valid Starlark !!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadProfiles(&starlark.Thread{Name: "profile-test"}, starlark.StringDict{}, false, "", rcPath)
	if err == nil {
		t.Fatal("invalid RC profile error was swallowed")
	}
}
