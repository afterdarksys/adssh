package starlarkext

import (
	"fmt"

	"go.starlark.net/starlark"
)

// toStarlark recursively converts Go values to Starlark values.
// Handles: nil, string, bool, int/int64, float64,
// map[string]interface{}, []interface{}, []string.
func toStarlark(v interface{}) starlark.Value {
	if v == nil {
		return starlark.None
	}
	switch val := v.(type) {
	case string:
		return starlark.String(val)
	case *string:
		if val == nil {
			return starlark.None
		}
		return starlark.String(*val)
	case bool:
		return starlark.Bool(val)
	case int:
		return starlark.MakeInt(val)
	case int32:
		return starlark.MakeInt64(int64(val))
	case int64:
		return starlark.MakeInt64(val)
	case *int32:
		if val == nil {
			return starlark.None
		}
		return starlark.MakeInt64(int64(*val))
	case *int64:
		if val == nil {
			return starlark.None
		}
		return starlark.MakeInt64(*val)
	case float64:
		return starlark.Float(val)
	case map[string]interface{}:
		d := starlark.NewDict(len(val))
		for k, v2 := range val {
			_ = d.SetKey(starlark.String(k), toStarlark(v2))
		}
		return d
	case map[string]string:
		d := starlark.NewDict(len(val))
		for k, v2 := range val {
			_ = d.SetKey(starlark.String(k), starlark.String(v2))
		}
		return d
	case []interface{}:
		l := make([]starlark.Value, len(val))
		for i, v2 := range val {
			l[i] = toStarlark(v2)
		}
		return starlark.NewList(l)
	case []string:
		l := make([]starlark.Value, len(val))
		for i, s := range val {
			l[i] = starlark.String(s)
		}
		return starlark.NewList(l)
	default:
		return starlark.String(fmt.Sprintf("%v", val))
	}
}

// strDeref safely dereferences a *string, returning "" for nil.
func strDeref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// makeDict builds a Starlark dict from a flat list of key, value pairs.
// Panics if an odd number of arguments is provided (programming error).
func makeDict(pairs ...interface{}) *starlark.Dict {
	if len(pairs)%2 != 0 {
		panic("makeDict: odd number of arguments")
	}
	d := starlark.NewDict(len(pairs) / 2)
	for i := 0; i < len(pairs); i += 2 {
		key := pairs[i].(string)
		_ = d.SetKey(starlark.String(key), toStarlark(pairs[i+1]))
	}
	return d
}
