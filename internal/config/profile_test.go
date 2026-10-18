package config

import (
	"os"
	"path/filepath"
	"strings"
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
	if v, ok := got["KEYMAP"].(starlark.String); !ok || string(v) != "emacs" {
		t.Fatalf("KEYMAP = %v, want \"emacs\"", got["KEYMAP"])
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

// A broken profile is reported with its file and line, and the startup files
// after it still load.
func TestLoadProfilesContinuesAfterError(t *testing.T) {
	dir := t.TempDir()
	profile := filepath.Join(dir, ".adsshprofile")
	rc := filepath.Join(dir, ".adsshrc")
	if err := os.WriteFile(profile, []byte("early = 1\n\nfail(\"bad profile\")\nlate = 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rc, []byte("from_rc = 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadProfiles(&starlark.Thread{Name: "test"}, starlark.StringDict{}, false, profile, rc)
	if err == nil {
		t.Fatal("profile error was swallowed")
	}
	if !strings.Contains(err.Error(), profile+":3:") {
		t.Fatalf("error %q does not name %s line 3", err, profile)
	}
	if got["from_rc"] != starlark.MakeInt(3) {
		t.Fatalf("rc after the broken profile did not load: %v", got["from_rc"])
	}
	if got["early"] != starlark.MakeInt(1) {
		t.Fatalf("bindings before the error were dropped: %v", got["early"])
	}
}
