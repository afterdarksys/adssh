package starlarkext

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
)

// The str namespace shadows the builtin str; calling it must still convert.
func TestStrNamespaceCallsBuiltinStr(t *testing.T) {
	g := runScript(t, `
a = str(5)
b = str.upper("a")
c = str.split("x y")
d = str(None)
`)
	assertStr(t, g, "a", "5")
	assertStr(t, g, "b", "A")
	assertStr(t, g, "d", "None")
	if g["c"].String() != `["x", "y"]` {
		t.Fatalf("c = %v", g["c"])
	}

	// Ungoverned globals (no engine) keep the call too.
	env := starlark.StringDict{}
	SetupExtensions(ExtensionOptions{Env: env})
	v, err := starlark.Eval(&starlark.Thread{Name: "t"}, "<t>", `str(5) + str["upper"]("b")`, env)
	if err != nil || v != starlark.String("5B") {
		t.Fatalf("ungoverned str(5) = %v, %v", v, err)
	}
}

// str.* members stay governed as starlark.str.<fn> under the callable namespace.
func TestStrNamespaceStillGoverned(t *testing.T) {
	eng, err := security.NewEngine(security.EngineConfig{PolicySource: []byte(`
package adssh.authz
default allow = false
allow { input.command != "starlark.str.upper" }
deny_reason = "upper denied" { input.command == "starlark.str.upper" }
`)})
	if err != nil {
		t.Fatal(err)
	}
	env := starlark.StringDict{}
	SetupExtensions(ExtensionOptions{Env: env})
	GovernStarlarkGlobalsInPlace(eng, env)
	th := &starlark.Thread{Name: "t"}
	for _, src := range []string{`str.upper("a")`, `str["upper"]("a")`, `str.get("upper")("a")`} {
		if _, err := starlark.Eval(th, "<t>", src, env); err == nil || !strings.Contains(err.Error(), "upper denied") {
			t.Fatalf("%s: err = %v, want policy denial", src, err)
		}
	}
	if v, err := starlark.Eval(th, "<t>", `str(7)`, env); err != nil || v != starlark.String("7") {
		t.Fatalf("str(7) = %v, %v", v, err)
	}
}

func TestJSONParseKeepsIntegers(t *testing.T) {
	g := runScript(t, `
v = data.json_parse('{"a": 1, "b": 1.5, "c": [2, -3], "d": 12345678901234567890, "e": 1e3}')
ta = type(v["a"])
tb = type(v["b"])
tc = type(v["c"][1])
td = type(v["d"])
te = type(v["e"])
y = data.yaml_parse("n: 4\nf: 2.5\n")
tn = type(y["n"])
tf = type(y["f"])
`)
	for name, want := range map[string]string{"ta": "int", "tb": "float", "tc": "int", "td": "int", "te": "float", "tn": "int", "tf": "float"} {
		assertStr(t, g, name, want)
	}
	if _, err := runScriptErr(t, false, `data.json_parse('{"a": 1} trailing')`); err == nil {
		t.Fatal("trailing data accepted")
	}
}

func TestExecJSONKeepsIntegers(t *testing.T) {
	env := execEnv(t, allowAllEngine(t), false)
	g, err := evalExec(t, env, `
v = sys["exec_json"]("echo '{\"n\": 1, \"f\": 0.5}'")
tn = type(v["n"])
tf = type(v["f"])
s = str(v["n"])
`)
	if err != nil {
		t.Fatalf("exec_json: %v", err)
	}
	assertStr(t, g, "tn", "int")
	assertStr(t, g, "tf", "float")
	assertStr(t, g, "s", "1")
}

func TestExecCmdErrorIncludesOutput(t *testing.T) {
	env := execEnv(t, allowAllEngine(t), false)
	_, err := evalExec(t, env, `sys["exec_cmd"]("echo first-line; echo boom-detail; exit 3")`)
	if err == nil {
		t.Fatal("non-zero exit succeeded")
	}
	if !strings.Contains(err.Error(), "boom-detail") || !strings.Contains(err.Error(), "exit status 3") {
		t.Fatalf("error = %v, want exit status and output", err)
	}

	// Long output is cut to its tail.
	_, err = evalExec(t, env, `sys["exec_cmd"]("i=0; while [ $i -lt 2000 ]; do echo line-$i; i=$((i+1)); done; echo last-line; exit 1")`)
	if err == nil || !strings.Contains(err.Error(), "last-line") || strings.Contains(err.Error(), "line-0\n") {
		t.Fatalf("long output error = %.300v", err)
	}
	if len(err.Error()) > 5000 {
		t.Fatalf("error not truncated: %d bytes", len(err.Error()))
	}
}

func TestDataDumpSerializes(t *testing.T) {
	g := runScript(t, `
j = data.json_dump({"b": [1, 2.5, True, None], "a": ("x", "y"), "c": {"z": 1, "k": "<v&>"}})
round = data.json_dump(data.json_parse(j))
y = data.yaml_dump({"b": 1, "a": ["x", 2.5, False, None]})
yround = data.yaml_dump(data.yaml_parse(y))
`)
	assertStr(t, g, "j", `{"a":["x","y"],"b":[1,2.5,true,null],"c":{"k":"<v&>","z":1}}`)
	assertStr(t, g, "y", "a:\n    - x\n    - 2.5\n    - false\n    - null\nb: 1\n")
	// Parsed dicts have no fixed order; dumping them again must not matter.
	if g["round"] != g["j"] {
		t.Fatalf("json round trip = %v, want %v", g["round"], g["j"])
	}
	if g["yround"] != g["y"] {
		t.Fatalf("yaml round trip = %v, want %v", g["yround"], g["y"])
	}
	for _, src := range []string{
		`data.json_dump(len)`,
		`data.json_dump({"f": lambda: 1})`,
		`data.yaml_dump(len)`,
		`data.json_dump({1: "x"})`,
	} {
		if _, err := runScriptErr(t, false, src); err == nil {
			t.Fatalf("%s: expected an error", src)
		}
	}
}

// Governing the globals twice must not wrap the governed str namespace again.
func TestGovernTwiceKeepsStrCallable(t *testing.T) {
	eng, err := security.NewEngine(security.EngineConfig{PolicySource: []byte("package adssh.authz\ndefault allow = true\n")})
	if err != nil {
		t.Fatal(err)
	}
	globals := starlark.StringDict{}
	SetupExtensions(ExtensionOptions{Env: globals})
	GovernStarlarkGlobalsInPlace(eng, globals)
	first := globals["str"]
	GovernStarlarkGlobalsInPlace(eng, globals)
	if globals["str"] != first {
		t.Fatal("a second governance pass rewrapped str")
	}
	v, err := starlark.Eval(&starlark.Thread{Name: "t"}, "t", `str(7)`, globals)
	if err != nil || v.String() != `"7"` {
		t.Fatalf("str(7) = %v, %v", v, err)
	}
}

// An integer with more digits than maxJSONIntDigits parses as a float, not a
// slow big.Int.
func TestJSONHugeIntegerIsBounded(t *testing.T) {
	huge := strings.Repeat("9", maxJSONIntDigits+1)
	if _, ok := GoToStarlark(json.Number(huge)).(starlark.Float); !ok {
		t.Fatal("an over-long integer did not become a float")
	}
	if _, ok := GoToStarlark(json.Number("123")).(starlark.Int); !ok {
		t.Fatal("a normal integer did not stay an int")
	}
}
