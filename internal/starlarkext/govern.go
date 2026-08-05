package starlarkext

import (
	"fmt"
	"sort"
	"strings"

	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
)

// GovernStarlarkGlobals wraps Starlark-callable values so every builtin reached
// through a script, profile, REPL, -c invocation, or MCP eval is independently
// authorized by the configured security engine.
func GovernStarlarkGlobals(sec *security.Engine, globals starlark.StringDict) starlark.StringDict {
	if sec == nil {
		return globals
	}
	governed := make(starlark.StringDict, len(globals))
	for name, value := range globals {
		governed[name] = GovernStarlarkValue(sec, "starlark."+name, value)
	}
	return governed
}

// GovernStarlarkGlobalsInPlace replaces the values in globals with governed
// wrappers while preserving the map identity captured by shell interceptors.
func GovernStarlarkGlobalsInPlace(sec *security.Engine, globals starlark.StringDict) {
	if sec == nil {
		return
	}
	for name, value := range globals {
		globals[name] = GovernStarlarkValue(sec, "starlark."+name, value)
	}
}

func GovernStarlarkValue(sec *security.Engine, path string, value starlark.Value) starlark.Value {
	switch value := value.(type) {
	case *starlark.Builtin:
		if !strings.HasSuffix(path, "."+value.Name()) {
			path += "." + value.Name()
		}
		return starlark.NewBuiltin(value.Name(), func(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := AuthorizeStarlarkOperation(sec, path, args, kwargs); err != nil {
				return nil, err
			}
			result, err := starlark.Call(thread, value, args, kwargs)
			if err != nil {
				return nil, err
			}
			return GovernStarlarkValue(sec, path, result), nil
		})
	case *starlark.Dict:
		return &GovernedStarlarkDict{Sec: sec, Path: path, Dict: value}
	case *starlark.List:
		items := make([]starlark.Value, value.Len())
		for index := range items {
			items[index] = GovernStarlarkValue(sec, fmt.Sprintf("%s[%d]", path, index), value.Index(index))
		}
		return starlark.NewList(items)
	case starlark.Tuple:
		items := make(starlark.Tuple, len(value))
		for index, item := range value {
			items[index] = GovernStarlarkValue(sec, fmt.Sprintf("%s[%d]", path, index), item)
		}
		return items
	case starlark.String, starlark.Bool, starlark.Int, starlark.Float, starlark.NoneType, *starlark.Set:
		return value
	case starlark.HasAttrs:
		return &GovernedStarlarkAttrs{Sec: sec, Path: path, Value: value, Attrs: value}
	default:
		return value
	}
}

func AuthorizeStarlarkOperation(sec *security.Engine, path string, args starlark.Tuple, kwargs []starlark.Tuple) error {
	policyArgs := make([]string, 0, len(args)+len(kwargs))
	for index, value := range args {
		policyArgs = append(policyArgs, fmt.Sprintf("arg%d=%s", index, value.String()))
	}
	keywordArgs := make([]string, 0, len(kwargs))
	for _, keyword := range kwargs {
		keywordArgs = append(keywordArgs, fmt.Sprintf("%s=%s", keyword[0], keyword[1]))
	}
	sort.Strings(keywordArgs)
	policyArgs = append(policyArgs, keywordArgs...)

	return sec.AuthorizeCommand(append([]string{path}, policyArgs...), "")
}

func childStarlarkPath(path string, key starlark.Value) string {
	name := key.String()
	if text, ok := starlark.AsString(key); ok {
		name = text
	}
	name = strings.ReplaceAll(name, " ", "_")
	return path + "." + name
}

type GovernedStarlarkDict struct {
	Sec  *security.Engine
	Path string
	Dict *starlark.Dict
}

func (d *GovernedStarlarkDict) String() string        { return d.Dict.String() }
func (d *GovernedStarlarkDict) Type() string          { return d.Dict.Type() }
func (d *GovernedStarlarkDict) Freeze()               { d.Dict.Freeze() }
func (d *GovernedStarlarkDict) Truth() starlark.Bool  { return d.Dict.Truth() }
func (d *GovernedStarlarkDict) Hash() (uint32, error) { return d.Dict.Hash() }
func (d *GovernedStarlarkDict) Len() int              { return d.Dict.Len() }
func (d *GovernedStarlarkDict) Iterate() starlark.Iterator {
	return d.Dict.Iterate()
}
func (d *GovernedStarlarkDict) Items() []starlark.Tuple {
	items := d.Dict.Items()
	for index, item := range items {
		items[index] = starlark.Tuple{item[0], GovernStarlarkValue(d.Sec, childStarlarkPath(d.Path, item[0]), item[1])}
	}
	return items
}
func (d *GovernedStarlarkDict) Get(key starlark.Value) (starlark.Value, bool, error) {
	value, found, err := d.Dict.Get(key)
	if err != nil || !found {
		return value, found, err
	}
	return GovernStarlarkValue(d.Sec, childStarlarkPath(d.Path, key), value), true, nil
}
func (d *GovernedStarlarkDict) SetKey(key, value starlark.Value) error {
	return d.Dict.SetKey(key, value)
}
func (d *GovernedStarlarkDict) Attr(name string) (starlark.Value, error) {
	value, err := d.Dict.Attr(name)
	if err != nil || value == nil {
		return value, err
	}
	return GovernStarlarkValue(d.Sec, d.Path+"."+name, value), nil
}
func (d *GovernedStarlarkDict) AttrNames() []string { return d.Dict.AttrNames() }

type GovernedStarlarkAttrs struct {
	Sec   *security.Engine
	Path  string
	Value starlark.Value
	Attrs starlark.HasAttrs
}

func (v *GovernedStarlarkAttrs) String() string        { return v.Value.String() }
func (v *GovernedStarlarkAttrs) Type() string          { return v.Value.Type() }
func (v *GovernedStarlarkAttrs) Freeze()               { v.Value.Freeze() }
func (v *GovernedStarlarkAttrs) Truth() starlark.Bool  { return v.Value.Truth() }
func (v *GovernedStarlarkAttrs) Hash() (uint32, error) { return v.Value.Hash() }
func (v *GovernedStarlarkAttrs) Attr(name string) (starlark.Value, error) {
	value, err := v.Attrs.Attr(name)
	if err != nil || value == nil {
		return value, err
	}
	return GovernStarlarkValue(v.Sec, v.Path+"."+name, value), nil
}
func (v *GovernedStarlarkAttrs) AttrNames() []string { return v.Attrs.AttrNames() }
