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

// The default rc calls set_keymap before the REPL defines it; that must load
// cleanly and record the choice for the REPL.
func TestDefaultRCLoadsAndRecordsKeymap(t *testing.T) {
	rc := filepath.Join(t.TempDir(), ".adsshrc") // missing: LoadProfiles writes defaultRC
	env := starlark.StringDict{}
	got, err := LoadProfiles(&starlark.Thread{Name: "test"}, env, false, "", rc)
	if err != nil {
		t.Fatalf("default rc failed to load: %v", err)
	}
	if v, ok := got["KEYMAP"].(starlark.String); !ok || string(v) != "vi" {
		t.Fatalf("KEYMAP = %v, want \"vi\"", got["KEYMAP"])
	}
}

func TestProfileSetKeymapRejectsUnknownMode(t *testing.T) {
	rc := filepath.Join(t.TempDir(), ".adsshrc")
	if err := os.WriteFile(rc, []byte(`set_keymap("nano")`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProfiles(&starlark.Thread{Name: "test"}, starlark.StringDict{}, false, "", rc); err == nil {
		t.Fatal("unknown keymap accepted")
	}
}
