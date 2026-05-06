package starlarkext

import (
	"encoding/json"
	"fmt"
	"go.starlark.net/starlark"
	"gopkg.in/yaml.v3"
)

func builtinJSONParse(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "data", &data); err != nil {
		return nil, err
	}
	var out interface{}
	if err := json.Unmarshal([]byte(data), &out); err != nil {
		return nil, fmt.Errorf("json parse error: %v", err)
	}
	return GoToStarlark(out), nil
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
	case int:
		return starlark.MakeInt(val)
	case string:
		return starlark.String(val)
	case []interface{}:
		list := starlark.NewList(nil)
		for _, item := range val {
			list.Append(GoToStarlark(item))
		}
		return list
	case map[string]interface{}:
		dict := starlark.NewDict(len(val))
		for k, v := range val {
			dict.SetKey(starlark.String(k), GoToStarlark(v))
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
	var cleanOut interface{}
	json.Unmarshal(jsonBytes, &cleanOut)

	return GoToStarlark(cleanOut), nil
}
