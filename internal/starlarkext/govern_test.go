package starlarkext

import (
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
)

func TestRestrictedModeDoesNotExposeLoadPlugin(t *testing.T) {
	globals := starlark.StringDict{}
	SetupExtensions(ExtensionOptions{Env: globals, Restricted: true})

	sysValue, ok := globals["sys"].(*starlark.Dict)
	if !ok {
		t.Fatalf("sys is %T, want *starlark.Dict", globals["sys"])
	}
	if value, found, err := sysValue.Get(starlark.String("load_plugin")); err != nil || found {
		t.Fatalf("restricted sys.load_plugin = (%v, %v, %v), want absent", value, found, err)
	}
}

func TestGovernStarlarkGlobalsAuthorizesBuiltins(t *testing.T) {
	eng, err := security.NewEngine(security.EngineConfig{PolicySource: []byte(`
package adssh.authz

default allow = false

allow {
    input.command != "starlark.sys.getenv"
}

deny_reason = "getenv denied" {
    input.command == "starlark.sys.getenv"
}
`)})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	globals := starlark.StringDict{}
	SetupExtensions(ExtensionOptions{Env: globals})
	GovernStarlarkGlobalsInPlace(eng, globals)

	_, err = starlark.Eval(&starlark.Thread{Name: "govern-test"}, "<test>", `sys["getenv"]("HOME")`, globals)
	if err == nil {
		t.Fatal("governed sys.getenv was allowed by a denying policy")
	}
	if !strings.Contains(err.Error(), "getenv denied") {
		t.Fatalf("error = %v, want policy denial reason", err)
	}
}
