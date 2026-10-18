package starlarkext

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"

	"go.starlark.net/starlark"
	"gopkg.in/yaml.v3"
)

// maxJSONIntDigits bounds the digits of a JSON integer parsed as an int.
const maxJSONIntDigits = 4300

func builtinJSONParse(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "data", &data); err != nil {
		return nil, err
	}
	out, err := decodeJSON([]byte(data))
	if err != nil {
		return nil, fmt.Errorf("json parse error: %v", err)
	}
	return GoToStarlark(out), nil
}

// decodeJSON parses one JSON document with numbers kept as json.Number, so
// GoToStarlark turns 1 into an int and only 1.5 or 1e3 into a float.
func decodeJSON(data []byte) (interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var out interface{}
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("invalid character after top-level value")
	}
	return out, nil
}

// GoToStarlark recursively converts Go native types to Starlark types
func GoToStarlark(v interface{}) starlark.Value {
	switch val := v.(type) {
	case nil:
		return starlark.None
	case bool:
		return starlark.Bool(val)
	case float64:
		return starlark.Float(val)
	case json.Number:
		// Integers become Starlark ints; one longer than maxJSONIntDigits
		// becomes a float, as Python caps int parsing, because decimal
		// big.Int conversion is quadratic in the digit count.
		if !strings.ContainsAny(string(val), ".eE") && len(val) <= maxJSONIntDigits {
			if i, ok := new(big.Int).SetString(string(val), 10); ok {
				return starlark.MakeBigInt(i)
			}
		}
		f, _ := val.Float64()
		return starlark.Float(f)
	case int:
		return starlark.MakeInt(val)
	case string:
		return starlark.String(val)
	case []interface{}:
		list := starlark.NewList(nil)
		for _, item := range val {
			_ = list.Append(GoToStarlark(item))
		}
		return list
	case map[string]interface{}:
		dict := starlark.NewDict(len(val))
		for k, v := range val {
			_ = dict.SetKey(starlark.String(k), GoToStarlark(v))
		}
		return dict
	default:
		return starlark.String(fmt.Sprintf("%v", val))
	}
}

func builtinYAMLParse(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "data", &data); err != nil {
		return nil, err
	}
	var out interface{}
	if err := yaml.Unmarshal([]byte(data), &out); err != nil {
		return nil, fmt.Errorf("yaml parse error: %v", err)
	}
	// yaml.v3 unmarshals into map[interface{}]interface{} which we need to convert to map[string]interface{}
	// The easiest way is JSON marshal/unmarshal
	jsonBytes, _ := json.Marshal(out)
	cleanOut, err := decodeJSON(jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("yaml parse error: %v", err)
	}

	return GoToStarlark(cleanOut), nil
}
