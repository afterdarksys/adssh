package starlarkext

import (
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
)

// session bags stay raw dicts so the shell and plugin loader can type-assert them.
func sessionBag(name string) bool {
	switch name {
	case "__custom_commands__", "__aliases__", "__completers__", "plugins":
		return true
	default:
		return false
	}
}

// GovernStarlarkGlobals wraps Starlark-callable values so every builtin reached
// through a script, profile, REPL, -c invocation, or MCP eval is independently
// authorized by the configured security engine.
func GovernStarlarkGlobals(sec *security.Engine, globals starlark.StringDict) starlark.StringDict {
	if sec == nil {
		return globals
	}
	governed := make(starlark.StringDict, len(globals))
	for name, value := range globals {
		if sessionBag(name) {
			governed[name] = value
			continue
		}
		governed[name] = governGlobal(sec, name, value)
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
		if sessionBag(name) {
			continue
		}
		globals[name] = governGlobal(sec, name, value)
	}
}

// governGlobal governs one global. A dict global is a namespace (sys, aws,
// crypto, ...): its keys are also attributes, so sys.exec_cmd(...) works as
// well as sys["exec_cmd"](...). Dicts that builtins return are data, not
// namespaces, and keep plain dict attributes.
func governGlobal(sec *security.Engine, name string, value starlark.Value) starlark.Value {
	if dict, ok := value.(*starlark.Dict); ok {
		return &GovernedStarlarkDict{Sec: sec, Path: "starlark." + name, Dict: dict, Namespace: true}
	}
	return GovernStarlarkValue(sec, "starlark."+name, value)
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
	// Namespace marks an adssh namespace (a dict global or a dict inside
	// one): a string key is also an attribute and wins over a dict method of
	// the same name. The governed path is the same either way, so
	// sys.exec_cmd and sys["exec_cmd"] are authorized as starlark.sys.exec_cmd.
	Namespace bool
}

// child governs a value reached through this dict. A dict inside a namespace
// is a namespace too (aws.ec2); everything else is governed as usual.
func (d *GovernedStarlarkDict) child(path string, value starlark.Value) starlark.Value {
	if dict, ok := value.(*starlark.Dict); ok && d.Namespace {
		return &GovernedStarlarkDict{Sec: d.Sec, Path: path, Dict: dict, Namespace: true}
	}
	return GovernStarlarkValue(d.Sec, path, value)
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
		items[index] = starlark.Tuple{item[0], d.child(childStarlarkPath(d.Path, item[0]), item[1])}
	}
	return items
}
func (d *GovernedStarlarkDict) Get(key starlark.Value) (starlark.Value, bool, error) {
	value, found, err := d.Dict.Get(key)
	if err != nil || !found {
		return value, found, err
	}
	return d.child(childStarlarkPath(d.Path, key), value), true, nil
}
func (d *GovernedStarlarkDict) SetKey(key, value starlark.Value) error {
	return d.Dict.SetKey(key, value)
}
func (d *GovernedStarlarkDict) Attr(name string) (starlark.Value, error) {
	if d.Namespace {
		key := starlark.String(name)
		if value, found, err := d.Dict.Get(key); err == nil && found {
			return d.child(childStarlarkPath(d.Path, key), value), nil
		}
		return d.namespaceMethod(name)
	}
	value, err := d.Dict.Attr(name)
	if err != nil || value == nil {
		return value, err
	}
	return GovernStarlarkValue(d.Sec, d.Path+"."+name, value), nil
}

// namespaceMethods are the dict methods a namespace keeps. Each returns
// members governed under their own path (starlark.sys.exec_cmd), so
// sys.get("exec_cmd") is checked exactly as sys.exec_cmd is. A namespace is
// not data: the methods that change a dict are refused.
var namespaceMethods = []string{"get", "items", "keys", "values"}

func (d *GovernedStarlarkDict) namespaceMethod(name string) (starlark.Value, error) {
	switch name {
	case "keys":
		return d.Dict.Attr(name)
	case "items":
		return starlark.NewBuiltin(name, func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs(b.Name(), args, kwargs); err != nil {
				return nil, err
			}
			items := d.Items()
			out := make([]starlark.Value, len(items))
			for i, item := range items {
				out[i] = item
			}
			return starlark.NewList(out), nil
		}), nil
	case "values":
		return starlark.NewBuiltin(name, func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs(b.Name(), args, kwargs); err != nil {
				return nil, err
			}
			items := d.Items()
			out := make([]starlark.Value, len(items))
			for i, item := range items {
				out[i] = item[1]
			}
			return starlark.NewList(out), nil
		}), nil
	case "get":
		return starlark.NewBuiltin(name, func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var key, dflt starlark.Value = nil, starlark.None
			if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &key, &dflt); err != nil {
				return nil, err
			}
			value, found, err := d.Get(key)
			if err != nil || !found {
				return dflt, err
			}
			return value, nil
		}), nil
	}
	if slices.Contains(d.Dict.AttrNames(), name) {
		return nil, fmt.Errorf("%s: namespace is read-only (no .%s)", strings.TrimPrefix(d.Path, "starlark."), name)
	}
	return nil, nil
}

func (d *GovernedStarlarkDict) AttrNames() []string {
	if !d.Namespace {
		return d.Dict.AttrNames()
	}
	names := append([]string(nil), namespaceMethods...)
	seen := map[string]bool{}
	for _, n := range names {
		seen[n] = true
	}
	for _, item := range d.Dict.Items() {
		if key, ok := starlark.AsString(item[0]); ok && !seen[key] {
			names = append(names, key)
			seen[key] = true
		}
	}
	sort.Strings(names)
	return names
}

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

// GovernReplacedGlobals governs every global whose value differs from before,
// the snapshot taken before a call that installs fresh builtins (as
// SetupExtensions does). Values that were already governed and left alone are
// not wrapped twice, so each call is authorized once.
// Threats: repl.Start re-ran SetupExtensions over globals its caller had
// governed, so the interactive REPL and SSH sessions ran every starlark.*
// builtin with no policy check (a policy denying starlark.crypto.sha256 held
// in -c and was ignored at the prompt).
func GovernReplacedGlobals(sec *security.Engine, globals, before starlark.StringDict) {
	if sec == nil {
		return
	}
	for name, value := range globals {
		if sessionBag(name) {
			continue
		}
		if old, ok := before[name]; ok && sameStarlarkValue(old, value) {
			continue
		}
		globals[name] = governGlobal(sec, name, value)
	}
}

// sameStarlarkValue reports whether a and b are the same value: the same
// pointer for reference types, equal for comparable values, the same backing
// array for slices.
func sameStarlarkValue(a, b starlark.Value) bool {
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	if va.Type() != vb.Type() {
		return false
	}
	switch va.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Chan:
		return va.Pointer() == vb.Pointer()
	case reflect.Slice:
		return va.Len() == vb.Len() && (va.Len() == 0 || va.Pointer() == vb.Pointer())
	}
	if va.Type().Comparable() {
		return a == b
	}
	return false
}
