package security

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/interp"
)

// A vbin that takes a bash builtin's name never reaches the exec handler:
// mvdan answers it first. Each such name must be in builtinNamedVBins (or
// the vbin renamed), so a new clash is a decision, not a silent dead command.
func TestVBinNamesClashingWithBuiltinsAreShadowed(t *testing.T) {
	for _, vb := range ListVBins() {
		name := vb.Name()
		if interp.IsBuiltin(name) && !builtinNamedVBins[name] {
			t.Errorf("vbin %q has a bash builtin's name and is not in builtinNamedVBins: mvdan will answer it", name)
		}
	}
	for name := range builtinNamedVBins {
		if !interp.IsBuiltin(name) {
			t.Errorf("%q is in builtinNamedVBins but is not a builtin; remove it", name)
		}
		if _, ok := Lookup(name); !ok {
			t.Errorf("%q is in builtinNamedVBins but no vbin has that name", name)
		}
	}
}

func TestBuiltinNamedVBinsRun(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)
	for _, src := range []string{"help", "help starlark", "history", "fc -l"} {
		stdout, stderr, err, _ := runShell(t, false, nil, src)
		if strings.Contains(stderr, "unsupported builtin") || strings.Contains(stdout, "unsupported builtin") {
			t.Fatalf("%s: mvdan answered it: %q", src, stderr)
		}
		if strings.Contains(stderr+stdout, "adssh-vbin") {
			t.Fatalf("%s: the internal name leaked: %q %q", src, stdout, stderr)
		}
		if src == "help" && (err != nil || stdout == "") {
			t.Fatalf("help: err %v, no output (stderr %q)", err, stderr)
		}
	}
}

// The gate sees the real name: a policy that denies help blocks it.
func TestBuiltinNamedVBinGatedByRealName(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)
	if err := LoadPolicy(writePolicy(t, `package adssh.authz
default allow = false
allow = true if { input.command != "help" }
`)); err != nil {
		t.Fatal(err)
	}
	stdout, _, err, _ := runShell(t, false, nil, "help")
	if err == nil || stdout != "" {
		t.Fatalf("denied help ran: err %v stdout %q", err, stdout)
	}
	// The same policy lets another command through, so the denial above is
	// the name check, not a broken policy.
	if _, _, err, rec := runShell(t, false, nil, "true_cmd"); err != nil || len(rec.calls) != 1 {
		t.Fatalf("allowed command: err %v calls %v", err, rec.calls)
	}
}

func TestUnshadowOnlyStripsTheInternalPrefix(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"adssh-vbin:help"}, {"x" + shadowPrefix + "help"}, {}} {
		if got := unshadowBuiltinVBin(args); strings.Join(got, " ") != strings.Join(args, " ") {
			t.Errorf("unshadow(%q) = %q, want unchanged", args, got)
		}
	}
	if got := unshadowBuiltinVBin([]string{shadowPrefix + "help", "starlark"}); got[0] != "help" || got[1] != "starlark" {
		t.Errorf("unshadow = %q", got)
	}
}

// A NUL-prefixed name built at run time (read keeps NUL) must not pass a
// deny-list policy as an unknown command and then be stripped back to the
// real one at exec.
func TestNULPrefixedNameDoesNotBypassDenyPolicy(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)
	if err := LoadPolicy(writePolicy(t, `package adssh.authz
default allow = false
allow { input.command != "denied_cmd" }
`)); err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{
		`printf '\0adssh-vbin:denied_cmd' | { read -r c; $c; }`,
		`printf 'x\0y' | { read -r c; allowed_cmd "$c"; }`,
	} {
		_, _, err, rec := runShell(t, false, nil, src)
		for _, call := range rec.calls {
			for _, a := range call {
				if strings.Contains(a, "denied_cmd") || strings.IndexByte(a, 0) >= 0 {
					t.Fatalf("%s: reached exec with %q (err %v)", src, call, err)
				}
			}
		}
	}
	if _, _, err, rec := runShell(t, false, nil, "allowed_cmd x"); err != nil || len(rec.calls) != 1 {
		t.Fatalf("plain allowed command: err %v calls %v", err, rec.calls)
	}
}
