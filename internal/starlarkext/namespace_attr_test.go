package starlarkext

import (
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
)

func governedTestGlobals(t *testing.T, policy string) starlark.StringDict {
	t.Helper()
	eng, err := security.NewEngine(security.EngineConfig{PolicySource: []byte(policy)})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	globals := starlark.StringDict{}
	SetupExtensions(ExtensionOptions{Env: globals})
	GovernStarlarkGlobalsInPlace(eng, globals)
	return globals
}

func evalStar(t *testing.T, globals starlark.StringDict, src string) (starlark.Value, error) {
	t.Helper()
	return starlark.Eval(&starlark.Thread{Name: "test"}, "test.star", src, globals)
}

const allowAll = "package adssh.authz\ndefault allow = true\n"

// The documented form sys.exec_cmd(...) works as well as sys["exec_cmd"](...).
func TestNamespaceKeysAreAttributes(t *testing.T) {
	globals := governedTestGlobals(t, allowAll)
	for _, src := range []string{`crypto.sha256("abc")`, `crypto["sha256"]("abc")`} {
		v, err := evalStar(t, globals, src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if s, _ := starlark.AsString(v); !strings.HasPrefix(s, "ba7816bf") {
			t.Fatalf("%s = %v", src, v)
		}
	}
	v, err := evalStar(t, globals, `[n for n in dir(sys) if n == "getenv"]`)
	if err != nil || v.String() != `["getenv"]` {
		t.Fatalf("dir(sys) = %v, %v; want getenv listed", v, err)
	}
	if _, err := evalStar(t, globals, `sys.no_such_function`); err == nil {
		t.Fatal("a missing namespace member resolved")
	}
}

// Attribute access is governed under the same path as indexing: a policy that
// denies starlark.sys.getenv blocks both spellings.
func TestNamespaceAttributeIsGoverned(t *testing.T) {
	globals := governedTestGlobals(t, `package adssh.authz
default allow = false
allow { input.command != "starlark.sys.getenv" }
`)
	for _, src := range []string{`sys.getenv("HOME")`, `sys["getenv"]("HOME")`} {
		if _, err := evalStar(t, globals, src); err == nil {
			t.Fatalf("%s ran under a policy that denies starlark.sys.getenv", src)
		}
	}
	if _, err := evalStar(t, globals, `crypto.sha256("x")`); err != nil {
		t.Fatalf("an allowed namespace call failed: %v", err)
	}
}

// A dict a builtin returns is data: its keys are not attributes, so a key
// named "get" does not hide the dict method.
func TestReturnedDictIsNotANamespace(t *testing.T) {
	globals := governedTestGlobals(t, allowAll)
	v, err := evalStar(t, globals, `data.json_parse('{"get": 1, "name": "x"}').get("name")`)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := starlark.AsString(v); s != "x" {
		t.Fatalf("get = %v, want the dict method's result", v)
	}
	if _, err := evalStar(t, globals, `data.json_parse('{"name": "x"}').name`); err == nil {
		t.Fatal("a returned dict's key resolved as an attribute")
	}
}

// Builtins installed after governance (as repl.Start's SetupExtensions does)
// are governed; values already governed and left alone are not wrapped again.
func TestGovernReplacedGlobals(t *testing.T) {
	eng, err := security.NewEngine(security.EngineConfig{PolicySource: []byte(`package adssh.authz
default allow = false
allow { input.command != "starlark.crypto.sha256" }
`)})
	if err != nil {
		t.Fatal(err)
	}
	globals := starlark.StringDict{"keep": starlark.NewBuiltin("keep", func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
		return starlark.None, nil
	})}
	SetupExtensions(ExtensionOptions{Env: globals})
	GovernStarlarkGlobalsInPlace(eng, globals)
	keep := globals["keep"]

	before := make(starlark.StringDict, len(globals))
	for k, v := range globals {
		before[k] = v
	}
	SetupExtensions(ExtensionOptions{Env: globals}) // reinstalls raw builtins
	if _, ok := globals["crypto"].(*starlark.Dict); !ok {
		t.Fatalf("crypto is %T after SetupExtensions; the test needs the raw dict", globals["crypto"])
	}
	GovernReplacedGlobals(eng, globals, before)

	if _, err := evalStar(t, globals, `crypto.sha256("abc")`); err == nil {
		t.Fatal("a builtin reinstalled after governance ran under a policy that denies it")
	}
	if !sameStarlarkValue(globals["keep"], keep) {
		t.Fatal("a value that was already governed was wrapped again")
	}
}

// Dict methods on a namespace keep the member's own policy path, so an
// exact-name deny cannot be sidestepped with sys.get("getenv") or values().
// The methods that would change a namespace are refused.
func TestNamespaceDictMethodsKeepPolicyPath(t *testing.T) {
	globals := governedTestGlobals(t, `package adssh.authz
default allow = false
allow { input.command != "starlark.sys.getenv" }
`)
	for _, src := range []string{
		`sys.get("getenv")("HOME")`,
		`sys.values()[list(sys.keys()).index("getenv")]("HOME")`,
		`[kv[1] for kv in sys.items() if kv[0] == "getenv"][0]("HOME")`,
	} {
		if _, err := evalStar(t, globals, src); err == nil || !strings.Contains(err.Error(), "denied") {
			t.Fatalf("%s: got %v, want a policy denial for starlark.sys.getenv", src, err)
		}
	}
	for _, src := range []string{`sys.pop("getenv")`, `sys.setdefault("x", 1)`, `sys.clear()`, `sys.update({})`, `sys.popitem()`} {
		if _, err := evalStar(t, globals, src); err == nil || !strings.Contains(err.Error(), "read-only") {
			t.Fatalf("%s: got %v, want read-only", src, err)
		}
	}
	if v, err := evalStar(t, globals, `sys.get("no_such", 7)`); err != nil || v.String() != "7" {
		t.Fatalf("get default: %v %v", v, err)
	}
	if v, err := evalStar(t, globals, `"getenv" in sys.keys()`); err != nil || v.String() != "True" {
		t.Fatalf("keys: %v %v", v, err)
	}
	// A namespace member named get (secrets.aws.get) is the member, not the method.
	if v, err := evalStar(t, globals, `type(secrets.aws.get)`); err != nil || v.String() != `"builtin_function_or_method"` {
		t.Fatalf("secrets.aws.get = %v, %v; want the builtin", v, err)
	}
}
