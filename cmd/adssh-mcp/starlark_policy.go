package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
)

type mcpSecurityEngineContextKey struct{}

func governStarlarkGlobals(sec *security.Engine, globals starlark.StringDict) starlark.StringDict {
	governed := make(starlark.StringDict, len(globals))
	for name, value := range globals {
		governed[name] = governStarlarkValue(sec, "starlark."+name, value)
	}
	return governed
}

func governStarlarkValue(sec *security.Engine, path string, value starlark.Value) starlark.Value {
	switch value := value.(type) {
	case *starlark.Builtin:
		if !strings.HasSuffix(path, "."+value.Name()) {
			path += "." + value.Name()
		}
		return starlark.NewBuiltin(value.Name(), func(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := authorizeStarlarkOperation(sec, path, args, kwargs); err != nil {
				return nil, err
			}
			result, err := starlark.Call(thread, value, args, kwargs)
			if err != nil {
				return nil, err
			}
			return governStarlarkValue(sec, path, result), nil
		})
	case *starlark.Dict:
		return &governedStarlarkDict{sec: sec, path: path, dict: value}
	case *starlark.List:
		items := make([]starlark.Value, value.Len())
		for index := range items {
			items[index] = governStarlarkValue(sec, fmt.Sprintf("%s[%d]", path, index), value.Index(index))
		}
		return starlark.NewList(items)
	case starlark.Tuple:
		items := make(starlark.Tuple, len(value))
		for index, item := range value {
			items[index] = governStarlarkValue(sec, fmt.Sprintf("%s[%d]", path, index), item)
		}
		return items
	case starlark.String, starlark.Bool, starlark.Int, starlark.Float, starlark.NoneType, *starlark.Set:
		return value
	case starlark.HasAttrs:
		return &governedStarlarkAttrs{sec: sec, path: path, value: value, attrs: value}
	default:
		return value
	}
}

func authorizeStarlarkOperation(sec *security.Engine, path string, args starlark.Tuple, kwargs []starlark.Tuple) error {
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

type governedStarlarkDict struct {
	sec  *security.Engine
	path string
	dict *starlark.Dict
}

func (d *governedStarlarkDict) String() string        { return d.dict.String() }
func (d *governedStarlarkDict) Type() string          { return d.dict.Type() }
func (d *governedStarlarkDict) Freeze()               { d.dict.Freeze() }
func (d *governedStarlarkDict) Truth() starlark.Bool  { return d.dict.Truth() }
func (d *governedStarlarkDict) Hash() (uint32, error) { return d.dict.Hash() }
func (d *governedStarlarkDict) Len() int              { return d.dict.Len() }
func (d *governedStarlarkDict) Iterate() starlark.Iterator {
	return d.dict.Iterate()
}
func (d *governedStarlarkDict) Items() []starlark.Tuple {
	items := d.dict.Items()
	for index, item := range items {
		items[index] = starlark.Tuple{item[0], governStarlarkValue(d.sec, childStarlarkPath(d.path, item[0]), item[1])}
	}
	return items
}
func (d *governedStarlarkDict) Get(key starlark.Value) (starlark.Value, bool, error) {
	value, found, err := d.dict.Get(key)
	if err != nil || !found {
		return value, found, err
	}
	return governStarlarkValue(d.sec, childStarlarkPath(d.path, key), value), true, nil
}
func (d *governedStarlarkDict) SetKey(key, value starlark.Value) error {
	return d.dict.SetKey(key, value)
}
func (d *governedStarlarkDict) Attr(name string) (starlark.Value, error) {
	value, err := d.dict.Attr(name)
	if err != nil || value == nil {
		return value, err
	}
	return governStarlarkValue(d.sec, d.path+"."+name, value), nil
}
func (d *governedStarlarkDict) AttrNames() []string { return d.dict.AttrNames() }

type governedStarlarkAttrs struct {
	sec   *security.Engine
	path  string
	value starlark.Value
	attrs starlark.HasAttrs
}

func (v *governedStarlarkAttrs) String() string        { return v.value.String() }
func (v *governedStarlarkAttrs) Type() string          { return v.value.Type() }
func (v *governedStarlarkAttrs) Freeze()               { v.value.Freeze() }
func (v *governedStarlarkAttrs) Truth() starlark.Bool  { return v.value.Truth() }
func (v *governedStarlarkAttrs) Hash() (uint32, error) { return v.value.Hash() }
func (v *governedStarlarkAttrs) Attr(name string) (starlark.Value, error) {
	value, err := v.attrs.Attr(name)
	if err != nil || value == nil {
		return value, err
	}
	return governStarlarkValue(v.sec, v.path+"."+name, value), nil
}
func (v *governedStarlarkAttrs) AttrNames() []string { return v.attrs.AttrNames() }
