package security

import (
	"os"
	"path/filepath"
	"testing"
)

// A policy in Rego v1 syntax must mean what it says. Compiled as v0, the
// `if` rule below loaded without error and allowed the excluded command.
func TestPolicyRegoV1RuleIsEnforced(t *testing.T) {
	for name, src := range map[string]string{
		"v1 if":         "package adssh.authz\ndefault allow = false\nallow = true if { input.command != \"help\" }\n",
		"v1 if, import": "package adssh.authz\nimport rego.v1\ndefault allow := false\nallow if input.command != \"help\"\n",
		"v0 body":       "package adssh.authz\ndefault allow = false\nallow { input.command != \"help\" }\n",
		"v0 keywords":   "package adssh.authz\nimport future.keywords.if\ndefault allow = false\nallow if { input.command != \"help\" }\n",
	} {
		t.Run(name, func(t *testing.T) {
			resetPolicy()
			t.Cleanup(resetPolicy)
			if err := LoadPolicy(writePolicy(t, src)); err != nil {
				t.Fatalf("load: %v", err)
			}
			if _, _, err, rec := runShell(t, false, nil, "help"); err == nil || len(rec.calls) != 0 {
				t.Fatalf("help was not denied: err %v", err)
			}
			if _, _, err, rec := runShell(t, false, nil, "ls"); err != nil || len(rec.calls) != 1 {
				t.Fatalf("ls was not allowed: err %v", err)
			}
		})
	}
}

// Every policy shipped in the repo still compiles.
func TestShippedPoliciesCompile(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "policy", "*.rego"))
	more, _ := filepath.Glob(filepath.Join("..", "policy", "*", "*.rego"))
	files = append(files, more...)
	if len(files) < 10 {
		t.Fatalf("found %d shipped policies, want the repo's", len(files))
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		e := &Engine{}
		if err := e.compilePolicy(f, data); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

// One v0-only rule must not make the file's v1 rules mean something else.
func TestMixedRegoSyntaxPolicyIsEnforced(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)
	if err := LoadPolicy(writePolicy(t, `package adssh.authz
default allow = false
allow = true if { input.command == "ls" }
deny_reason = "no" { input.command == "sudo" }
`)); err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, cmd := range []string{"rm", "sudo"} {
		if _, _, err, rec := runShell(t, false, nil, cmd); err == nil || len(rec.calls) != 0 {
			t.Fatalf("%s was not denied by a policy that allows only ls", cmd)
		}
	}
	if _, _, err, rec := runShell(t, false, nil, "ls"); err != nil || len(rec.calls) != 1 {
		t.Fatalf("ls was not allowed: err %v", err)
	}
}
