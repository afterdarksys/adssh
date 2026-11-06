package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRunSashEmergencyMissingSeed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ADSSH_SASH_EMERGENCY_SEED", filepath.Join(dir, "missing-seed"))
	t.Setenv("ADSSH_SASH_FLEET_PUB", filepath.Join(dir, "missing-pub"))
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	code := runSashEmergency(nil)
	os.Stderr = old
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if code != 2 || string(b) != "grant_bad_sig\n" {
		t.Fatalf("code %d stderr %q", code, b)
	}
}
