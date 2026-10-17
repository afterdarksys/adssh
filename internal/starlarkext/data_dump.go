package starlarkext

import (
	"bytes"
	"encoding/json"
	"fmt"

	"go.starlark.net/starlark"
	"gopkg.in/yaml.v3"
)

// data.json_dump(val) -> str. Compact JSON with sorted keys, so the same value
// always dumps to the same text. dict (string keys), list, tuple, str, int,
// float, bool and None convert; anything else (a function, a set, NaN) is an
// error. The value is converted under the data.validate size and depth caps.
func builtinJSONDump(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var val starlark.Value
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "val", &val); err != nil {
		return nil, err
	}
	doc, err := toJSONValue(val, true)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", b.Name(), err)
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false) // "<a&b>" stays readable, as jq prints it
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("%s: %v", b.Name(), err)
	}
	return starlark.String(bytes.TrimSuffix(out.Bytes(), []byte("\n"))), nil
}

// data.yaml_dump(val) -> str. Same values as json_dump; mapping keys sorted.
func builtinYAMLDump(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var val starlark.Value
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "val", &val); err != nil {
		return nil, err
	}
	doc, err := toJSONValue(val, false)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", b.Name(), err)
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", b.Name(), err)
	}
	return starlark.String(out), nil
}
