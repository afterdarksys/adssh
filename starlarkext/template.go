package starlarkext

import (
	"bytes"
	"fmt"
	"os"
	"text/template"

	"go.starlark.net/starlark"
)

// SetupTemplateAPI registers the template.* namespace into the Starlark environment.
//
// Starlark API:
//
//	template.render(tmpl="Hello {{.Name}}", data={"Name":"world"}) → string
//	template.render_file(path="/etc/adssh/tmpl.txt", data={})      → string
func SetupTemplateAPI(env starlark.StringDict) {
	d := starlark.NewDict(2)
	d.SetKey(starlark.String("render"), starlark.NewBuiltin("render", templateRender))
	d.SetKey(starlark.String("render_file"), starlark.NewBuiltin("render_file", templateRenderFile))
	env["template"] = d
}

// ── render ────────────────────────────────────────────────────────────────────

func templateRender(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var tmplStr string
	var dataDict *starlark.Dict
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"tmpl", &tmplStr,
		"data?", &dataDict,
	); err != nil {
		return nil, err
	}

	result, err := renderTemplate(tmplStr, dataDict)
	if err != nil {
		return nil, fmt.Errorf("template.render: %v", err)
	}
	return starlark.String(result), nil
}

// ── render_file ───────────────────────────────────────────────────────────────

func templateRenderFile(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	var dataDict *starlark.Dict
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"path", &path,
		"data?", &dataDict,
	); err != nil {
		return nil, err
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("template.render_file: read %q: %v", path, err)
	}

	result, err := renderTemplate(string(raw), dataDict)
	if err != nil {
		return nil, fmt.Errorf("template.render_file: %v", err)
	}
	return starlark.String(result), nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func renderTemplate(tmplStr string, dataDict *starlark.Dict) (string, error) {
	tmpl, err := template.New("t").Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("parse: %v", err)
	}

	var data interface{}
	if dataDict != nil {
		data = starlarkDictToGo(dataDict)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute: %v", err)
	}
	return buf.String(), nil
}
