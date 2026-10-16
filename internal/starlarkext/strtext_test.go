package starlarkext

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"go.starlark.net/starlark"
)

func TestStrSlugify(t *testing.T) {
	cases := []struct{ src, want string }{
		{`str["slugify"]("Crème Brûlée!")`, "creme-brulee"},
		{`str["slugify"]("  Hello,   World  ")`, "hello-world"},
		{`str["slugify"]("İstanbul ﬁle")`, "istanbul-file"},
		{`str["slugify"]("Ünïcödé--Têxt__here", sep="_")`, "unicode_text_here"},
		{`str["slugify"]("日本語 テスト")`, "日本語-テスト"},
		{`str["slugify"]("a b c d e f", max=5)`, "a-b-c"},
		{`str["slugify"]("abc def", max=4)`, "abc"},
		{`str["slugify"]("!!!")`, ""},
		{`str["slugify"]("A B", sep="")`, "ab"},
	}
	for _, tc := range cases {
		g, err := runScriptErr(t, false, "out = "+tc.src)
		if err != nil {
			t.Fatalf("%s: %v", tc.src, err)
		}
		assertStr(t, g, "out", tc.want)
	}
}

func TestStrSlugifyRejects(t *testing.T) {
	for _, src := range []string{
		`str["slugify"]("x", max=0)`,
		`str["slugify"]("x", max=100000)`,
		`str["slugify"]("x", sep="--------------------")`,
	} {
		if _, err := runScriptErr(t, false, src); err == nil {
			t.Fatalf("%s: expected an error", src)
		}
	}
}

func TestStrTemplate(t *testing.T) {
	g, err := runScriptErr(t, false, `
a = str["template"]("Hello {{.name}}, you are {{.age}}", {"name": "ada", "age": 36})
b = str["template"]("{{if gt .n 2}}big{{else}}small{{end}} {{printf \"%03d\" .n}}", {"n": 5})
c = str["template"]("{{range .xs}}[{{.}}]{{end}} {{len .xs}} {{index .m \"k\"}}", {"xs": ["a", "b"], "m": {"k": "v"}})
d = str["template"]("{{.missing}}", {}, strict=False)
e = str["template"]("{{define \"t\"}}T{{end}}{{template \"t\"}}", {})
f = str["template"]("{{eq .s \"x\"}}", {"s": data["json_parse"]('"x"')})
`)
	if err != nil {
		t.Fatalf("template: %v", err)
	}
	assertStr(t, g, "a", "Hello ada, you are 36")
	assertStr(t, g, "b", "big 005")
	assertStr(t, g, "c", "[a][b] 2 v")
	assertStr(t, g, "d", "<no value>")
	assertStr(t, g, "e", "T")
	assertStr(t, g, "f", "true")
}

func TestStrTemplateRejects(t *testing.T) {
	cases := []struct{ src, want string }{
		{`str["template"]("{{.missing}}", {})`, "missing"},
		{`str["template"]("{{template \"nope\"}}", {})`, "nope"},
		{`str["template"]("{{call .f}}", {"f": "x"})`, "disabled"},
		{`str["template"]("{{html .x}}", {"x": "<"})`, "disabled"},
		{`str["template"]("{{js .x}}", {"x": "<"})`, "disabled"},
		{`str["template"]("{{urlquery .x}}", {"x": "<"})`, "disabled"},
		{`str["template"]("{{range 1000000000}}{{end}}", {})`, "range over a number"},
		{`str["template"]("{{nosuchfunc}}", {})`, "nosuchfunc"},
		{`str["template"]("{{", {})`, "parse"},
		{`str["template"]("x", {1: 2})`, "key"},
	}
	for _, tc := range cases {
		_, err := runScriptErr(t, false, tc.src)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", tc.src, err, tc.want)
		}
	}
}

func TestStrTemplateOutputCap(t *testing.T) {
	env := governedEnv(t, false)
	env["XS"] = starlark.NewList(make([]starlark.Value, 0))
	items := make([]starlark.Value, 2048)
	for i := range items {
		items[i] = starlark.String(strings.Repeat("y", 1024))
	}
	env["XS"] = starlark.NewList(items)
	_, err := starlark.ExecFile(&starlark.Thread{Name: "t"}, "t.star", `str["template"]("{{range .xs}}{{.}}{{end}}", {"xs": XS})`, env)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want an output-cap failure", err)
	}
}

func TestStrTemplateSizeCap(t *testing.T) {
	env := governedEnv(t, false)
	env["BIG"] = starlark.String(strings.Repeat("x", maxTemplateBytes+1))
	if _, err := starlark.ExecFile(&starlark.Thread{Name: "t"}, "t.star", `str["template"](BIG, {})`, env); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want a size refusal", err)
	}
}

// Every way of putting a number in front of range is refused: literal,
// parenthesised, through a variable, through with, and an int from vars.
func TestStrTemplateRefusesRangeOverNumbers(t *testing.T) {
	cases := []struct{ src, want string }{
		{`str["template"]("{{range (300000000)}}{{end}}", {})`, "range"},
		{`str["template"]("{{range or 0 300000000}}{{end}}", {})`, "range"},
		{`str["template"]("{{range $i := 300000000}}{{end}}", {})`, "range"},
		{`str["template"]("{{$n := 300000000}}{{range $n}}{{end}}", {})`, "range over a number"},
		{`str["template"]("{{with 300000000}}{{range .}}{{end}}{{end}}", {})`, "range over a number"},
		{`str["template"]("{{range .n}}{{end}}", {"n": 300000000})`, "range over a number"},
		{`str["template"]("{{define \"t\"}}{{range .}}{{end}}{{end}}{{template \"t\" .n}}", {"n": 300000000})`, "range over a number"},
	}
	for _, tc := range cases {
		_, err := runScriptErr(t, false, tc.src)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", tc.src, err, tc.want)
		}
	}
}

// Ranges over fields, variables, dot and chains still work, and the inserted
// guard leaves values and nil template arguments unchanged.
func TestStrTemplateRangeGuardKeepsBehaviour(t *testing.T) {
	g, err := runScriptErr(t, false, `
a = str["template"]("{{range $i, $x := .xs}}{{$i}}{{$x}}{{end}}", {"xs": ["a", "b"]})
b = str["template"]("{{range .m}}{{.}}{{end}}", {"m": {"k": 1, "j": 2}})
c = str["template"]("{{with .xs}}{{range .}}{{.}}{{end}}{{end}}", {"xs": [1, 2]})
d = str["template"]("{{define \"t\"}}[{{.}}]{{end}}{{template \"t\"}}{{template \"t\" .n}}", {"n": 7})
e = str["template"]("{{range .xs}}x{{else}}empty{{end}}", {"xs": []})
f = str["template"]("{{if gt .n 2}}big{{end}}", {"n": 5})
`)
	if err != nil {
		t.Fatalf("template: %v", err)
	}
	assertStr(t, g, "a", "0a1b")
	assertStr(t, g, "b", "21")
	assertStr(t, g, "c", "12")
	assertStr(t, g, "d", "[<no value>][7]")
	assertStr(t, g, "e", "empty")
	assertStr(t, g, "f", "big")
}

// A template that writes nothing and loops far past the deadline must stop
// soon after the call returns: no worker goroutine is left running.
func TestStrTemplateTimedOutWorkerStops(t *testing.T) {
	old := templateDeadline
	templateDeadline = 50 * time.Millisecond
	t.Cleanup(func() { templateDeadline = old })

	env := governedEnv(t, false)
	items := make([]starlark.Value, 2000)
	for i := range items {
		items[i] = starlark.MakeInt(i)
	}
	env["XS"] = starlark.NewList(items)
	cases := []string{
		`str["template"]("{{range .xs}}{{range $.xs}}{{range $.xs}}{{end}}{{end}}{{end}}", {"xs": XS})`,
		`str["template"]("{{define \"t\"}}{{template \"t\" .}}{{template \"t\" .}}{{end}}{{template \"t\" .}}", {"xs": XS})`,
	}
	for _, src := range cases {
		runtime.GC()
		baseline := runtime.NumGoroutine()
		_, err := starlark.ExecFile(&starlark.Thread{Name: "t"}, "t.star", src, env)
		if err == nil || !strings.Contains(err.Error(), "time limit") {
			t.Fatalf("%s: err = %v, want a time-limit failure", src, err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for runtime.NumGoroutine() > baseline && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if n := runtime.NumGoroutine(); n > baseline {
			t.Fatalf("%s: %d goroutines after timeout, baseline %d: worker still running", src, n, baseline)
		}
	}
}
