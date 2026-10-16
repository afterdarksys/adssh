package starlarkext

import (
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
)

func runScriptErr(t *testing.T, restricted bool, src string) (starlark.StringDict, error) {
	t.Helper()
	env := governedEnv(t, restricted)
	return starlark.ExecFile(&starlark.Thread{Name: "test"}, "test.star", src, env)
}

func TestDataAssertType(t *testing.T) {
	g := runScript(t, `
a = data["assert_type"]({"k": 1}, "dict")
b = data["assert_type"](1.5, ["int", "float"])
c = data["assert_type"](data["json_parse"]('{"x": 1}'), "dict")
`)
	if g["b"] != starlark.Float(1.5) {
		t.Fatalf("b = %v, want 1.5", g["b"])
	}
	if g["a"].Type() != "dict" || g["c"].Type() != "dict" {
		t.Fatalf("a=%v c=%v, want dicts", g["a"], g["c"])
	}
}

func TestDataAssertTypeRejects(t *testing.T) {
	cases := []struct{ src, want string }{
		{`data["assert_type"]("x", "dict")`, "got string, want dict"},
		{`data["assert_type"](None, ["int", "float"])`, "got NoneType, want one of int, float"},
		{`data["assert_type"](1, [])`, "expected"},
		{`data["assert_type"](1, 3)`, "expected"},
		{`data["assert_type"](1, [""])`, "expected"},
	}
	for _, tc := range cases {
		_, err := runScriptErr(t, false, tc.src)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", tc.src, err, tc.want)
		}
	}
}

const personSchema = `{
  "type": "object",
  "required": ["name", "age"],
  "properties": {
    "name": {"type": "string", "minLength": 1},
    "age": {"type": "integer", "minimum": 0}
  },
  "additionalProperties": false
}`

func TestDataValidateValid(t *testing.T) {
	env := governedEnv(t, false)
	env["SCHEMA"] = starlark.String(personSchema)
	g, err := starlark.ExecFile(&starlark.Thread{Name: "t"}, "t.star", `
ok_str = data["validate"](SCHEMA, {"name": "ada", "age": 36})
ok_dict = data["validate"]({"type": "array", "items": {"type": "number"}}, [1, 2.5, 3])
ok_yaml = data["validate"]("type: object\nrequired: [a]\n", {"a": True})
`, env)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	for _, name := range []string{"ok_str", "ok_dict", "ok_yaml"} {
		if g[name] != starlark.True {
			t.Fatalf("%s = %v, want True", name, g[name])
		}
	}
}

func TestDataValidateErrors(t *testing.T) {
	env := governedEnv(t, false)
	env["SCHEMA"] = starlark.String(personSchema)
	g, err := starlark.ExecFile(&starlark.Thread{Name: "t"}, "t.star", `
errs = data["validate"](SCHEMA, {"name": "", "age": -1, "extra": 1})
paths = sorted([e["path"] for e in errs])
msgs = " | ".join([e["message"] for e in errs])
`, env)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	paths, ok := g["paths"].(*starlark.List)
	if !ok || paths.Len() < 3 {
		t.Fatalf("paths = %v, want at least 3 errors", g["paths"])
	}
	joined := g["paths"].String()
	for _, want := range []string{`"/age"`, `"/name"`} {
		if !strings.Contains(joined, want) {
			t.Fatalf("paths = %s, missing %s", joined, want)
		}
	}
	msgs, _ := starlark.AsString(g["msgs"])
	if !strings.Contains(msgs, "extra") {
		t.Fatalf("messages = %q, want the additionalProperties error", msgs)
	}
}

func TestDataValidateStrictFails(t *testing.T) {
	env := governedEnv(t, false)
	env["SCHEMA"] = starlark.String(personSchema)
	_, err := starlark.ExecFile(&starlark.Thread{Name: "t"}, "t.star", `data["validate"](SCHEMA, {"name": "x"}, strict=True)`, env)
	if err == nil || !strings.Contains(err.Error(), "age") {
		t.Fatalf("err = %v, want a strict failure naming age", err)
	}
}

// Any $ref that is not inside the schema must fail closed without touching
// the network or the filesystem.
func TestDataValidateRefusesExternalRefs(t *testing.T) {
	refs := []string{
		`https://example.invalid/schema.json`,
		`http://127.0.0.1:1/schema.json`,
		`file:///etc/passwd`,
		`other.json`,
		`/etc/hosts`,
	}
	for _, ref := range refs {
		env := governedEnv(t, false)
		env["REF"] = starlark.String(ref)
		_, err := starlark.ExecFile(&starlark.Thread{Name: "t"}, "t.star", `data["validate"]({"$ref": REF}, 1)`, env)
		if err == nil || !strings.Contains(err.Error(), "external $ref refused") {
			t.Fatalf("$ref %q: err = %v, want external $ref refused", ref, err)
		}
	}
	// A local $ref inside the schema still works.
	g := runScript(t, `
ok = data["validate"]({"$defs": {"n": {"type": "integer"}}, "$ref": "#/$defs/n"}, 3)
`)
	if g["ok"] != starlark.True {
		t.Fatalf("local $ref: %v, want True", g["ok"])
	}
}

func TestDataValidateSizeCaps(t *testing.T) {
	env := governedEnv(t, false)
	env["BIG"] = starlark.String(strings.Repeat(" ", maxValidateBytes+1))
	if _, err := starlark.ExecFile(&starlark.Thread{Name: "t"}, "t.star", `data["validate"](BIG, 1)`, env); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized schema: err = %v, want a size refusal", err)
	}
	env["BIGVAL"] = starlark.String(strings.Repeat("x", maxValidateBytes+1))
	if _, err := starlark.ExecFile(&starlark.Thread{Name: "t"}, "t.star", `data["validate"]({"type": "string"}, BIGVAL)`, env); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized document: err = %v, want a size refusal", err)
	}
}

func TestDataValidateRejectsBadInput(t *testing.T) {
	cases := []struct{ src, want string }{
		{`data["validate"]("{not json", 1)`, "schema"},
		{`data["validate"]({"type": 5}, 1)`, "schema"},
		{`data["validate"]({"type": "object"}, {1: 2})`, "key"},
		{`data["validate"]({}, float("nan"))`, "finite"},
		{`l = []
l.append(l)
data["validate"]({}, l)`, "depth"},
	}
	for _, tc := range cases {
		_, err := runScriptErr(t, false, tc.src)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", tc.src, err, tc.want)
		}
	}
}

func TestDataValidateDeadline(t *testing.T) {
	saved := boundedHook
	boundedHook = func() { time.Sleep(200 * time.Millisecond) }
	savedDeadline := validateDeadline
	validateDeadline = 20 * time.Millisecond
	defer func() { boundedHook, validateDeadline = saved, savedDeadline }()
	_, err := runScriptErr(t, false, `data["validate"]({"type": "integer"}, 1)`)
	if err == nil || !strings.Contains(err.Error(), "time limit") {
		t.Fatalf("err = %v, want a time-limit failure", err)
	}
}

// Pure builtins stay available in restricted sessions.
func TestConfigDataAvailableWhenRestricted(t *testing.T) {
	g, err := runScriptErr(t, true, `
a = data["assert_type"](1, "int")
v = data["validate"]({"type": "integer"}, 1)
s = str["slugify"]("Hello World")
r = str["template"]("{{.x}}", {"x": "y"})
`)
	if err != nil {
		t.Fatalf("restricted: %v", err)
	}
	if g["v"] != starlark.True {
		t.Fatalf("v = %v", g["v"])
	}
}

// The data/str namespaces map onto existing capability groups.
func TestConfigDataCapabilities(t *testing.T) {
	for path, want := range map[string]string{
		"starlark.data.validate":    "data",
		"starlark.data.assert_type": "data",
		"starlark.str.slugify":      "strings",
		"starlark.str.template":     "strings",
		"starlark.log.info":         "audit",
		"starlark.net.dial_udp":     "net",
	} {
		got := security.ClassifyCapabilities(path)
		found := false
		for _, c := range got {
			if c == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("ClassifyCapabilities(%q) = %v, want it to include %q", path, got, want)
		}
	}
}
