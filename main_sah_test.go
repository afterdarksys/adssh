package main

import (
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/engine"
	"github.com/afterdarksys/adssh/security"
)

func TestSAHExecuteRequiresPolicyAndRejectsVirtual(t *testing.T) {
	eng, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = sahExecute(eng.Security(), "sess", []string{"/bin/echo", "hi"})
	if err == nil || err.Error() != "policy_required" {
		t.Fatalf("no policy: %v", err)
	}

	eng, err = engine.New(engine.Config{
		EngineConfig: security.EngineConfig{
			PolicySource: []byte(`package adssh.authz
default allow = false
allow { input.command == "/bin/echo" }
`),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !eng.Security().PolicyLoaded() {
		t.Fatal("policy not loaded")
	}
	_, _, _, err = sahExecute(eng.Security(), "sess", []string{"lease", "--from", "env:X"})
	if err == nil || err.Error() != "command_rejected" {
		t.Fatalf("vbin: %v", err)
	}
	_, _, _, err = sahExecute(eng.Security(), "sess", []string{"/bin/not-allowed"})
	if err == nil || err.Error() != "policy_denied" {
		t.Fatalf("deny: %v", err)
	}
	stdout, stderr, code, err := sahExecute(eng.Security(), "sess", []string{"/bin/echo", "hi"})
	if err != nil || code != 0 || strings.TrimSpace(stdout) != "hi" {
		t.Fatalf("echo: code %d err %v stdout %q stderr %q", code, err, stdout, stderr)
	}
}
