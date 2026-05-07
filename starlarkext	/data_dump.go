package starlarkext

import (
	"encoding/json"
	"go.starlark.net/starlark"
	"gopkg.in/yaml.v3"
)

func builtinJSONDump(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	// Dummy implementation for prototype that just takes a starlark value and stringifies it
	var val starlark.Value
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "val", &val); err != nil {
		return nil, err
	}
	// In a real impl, we'd recursively convert starlark.Dict/List to Go types then json.Marshal
	out, _ := json.Marshal(val.String())
	return starlark.String(string(out)), nil
}

func builtinYAMLDump(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var val starlark.Value
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "val", &val); err != nil {
		return nil, err
	}
	out, _ := yaml.Marshal(val.String())
	return starlark.String(string(out)), nil
}
