package starlarkext

// Governed string helpers for Starlark.
//
// Starlark's native string type already carries many methods; this `str`
// namespace adds the shell-ish, procedural helpers scripts reach for when
// massaging command output (fields, sprintf, trim variants). Every builtin is
// pure (no I/O, no process, no network) and is classified into the `strings`
// capability group, so a capability policy that allows `strings` allows all of
// them and nothing more.

import (
	"fmt"
	"strings"

	"go.starlark.net/starlark"
)

// SetupStringsAPI injects the `str` namespace into env.
func SetupStringsAPI(env starlark.StringDict) {
	d := starlark.NewDict(16)
	set := func(name string, fn func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error)) {
		_ = d.SetKey(starlark.String(name), starlark.NewBuiltin(name, fn))
	}
	set("split", strSplit)
	set("join", strJoin)
	set("fields", strFields)
	set("trim", strTrim)
	set("trim_prefix", strTrimPrefix)
	set("trim_suffix", strTrimSuffix)
	set("contains", strContains)
	set("has_prefix", strHasPrefix)
	set("has_suffix", strHasSuffix)
	set("replace", strReplace)
	set("lower", strLower)
	set("upper", strUpper)
	set("sprintf", strSprintf)
	set("slugify", strSlugify)   // strtext.go
	set("template", strTemplate) // strtext.go
	env["str"] = d
}

// str.split(s, sep) -> list. With no sep (or ""), splits on whitespace runs
// (like str.fields) rather than producing empty elements.
func strSplit(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s, sep string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "s", &s, "sep?", &sep); err != nil {
		return nil, err
	}
	var parts []string
	if sep == "" {
		parts = strings.Fields(s)
	} else {
		parts = strings.Split(s, sep)
	}
	return stringList(parts), nil
}

// str.fields(s) -> list of whitespace-separated tokens.
func strFields(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "s", &s); err != nil {
		return nil, err
	}
	return stringList(strings.Fields(s)), nil
}

// str.join(parts, sep="") -> string. Accepts any iterable of strings.
func strJoin(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var iter starlark.Iterable
	var sep string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "parts", &iter, "sep?", &sep); err != nil {
		return nil, err
	}
	var parts []string
	it := iter.Iterate()
	defer it.Done()
	var v starlark.Value
	for it.Next(&v) {
		s, ok := starlark.AsString(v)
		if !ok {
			return nil, fmt.Errorf("str.join: element is not a string: %s", v.Type())
		}
		parts = append(parts, s)
	}
	return starlark.String(strings.Join(parts, sep)), nil
}

func strTrim(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s, cutset string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "s", &s, "cutset?", &cutset); err != nil {
		return nil, err
	}
	if cutset == "" {
		return starlark.String(strings.TrimSpace(s)), nil
	}
	return starlark.String(strings.Trim(s, cutset)), nil
}

func strTrimPrefix(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s, prefix string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "s", &s, "prefix", &prefix); err != nil {
		return nil, err
	}
	return starlark.String(strings.TrimPrefix(s, prefix)), nil
}

func strTrimSuffix(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s, suffix string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "s", &s, "suffix", &suffix); err != nil {
		return nil, err
	}
	return starlark.String(strings.TrimSuffix(s, suffix)), nil
}

func strContains(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s, substr string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "s", &s, "substr", &substr); err != nil {
		return nil, err
	}
	return starlark.Bool(strings.Contains(s, substr)), nil
}

func strHasPrefix(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s, prefix string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "s", &s, "prefix", &prefix); err != nil {
		return nil, err
	}
	return starlark.Bool(strings.HasPrefix(s, prefix)), nil
}

func strHasSuffix(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s, suffix string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "s", &s, "suffix", &suffix); err != nil {
		return nil, err
	}
	return starlark.Bool(strings.HasSuffix(s, suffix)), nil
}

// str.replace(s, old, new, n=-1) -> string. n<0 replaces all.
func strReplace(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s, old, replacement string
	n := -1
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "s", &s, "old", &old, "new", &replacement, "n?", &n); err != nil {
		return nil, err
	}
	return starlark.String(strings.Replace(s, old, replacement, n)), nil
}

func strLower(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "s", &s); err != nil {
		return nil, err
	}
	return starlark.String(strings.ToLower(s)), nil
}

func strUpper(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "s", &s); err != nil {
		return nil, err
	}
	return starlark.String(strings.ToUpper(s)), nil
}

// str.sprintf(format, *args) -> string. Formats %-verbs against string/int/
// float/bool args; other Starlark values render via their String().
func strSprintf(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("str.sprintf: format is required")
	}
	if len(kwargs) != 0 {
		return nil, fmt.Errorf("str.sprintf: keyword arguments are not supported")
	}
	format, ok := starlark.AsString(args[0])
	if !ok {
		return nil, fmt.Errorf("str.sprintf: format must be a string")
	}
	rest := make([]interface{}, 0, len(args)-1)
	for _, a := range args[1:] {
		rest = append(rest, goValue(a))
	}
	return starlark.String(fmt.Sprintf(format, rest...)), nil
}

// goValue unwraps a Starlark scalar to a Go value fmt can format naturally;
// anything else falls back to its Starlark String() form.
func goValue(v starlark.Value) interface{} {
	switch t := v.(type) {
	case starlark.String:
		return string(t)
	case starlark.Bool:
		return bool(t)
	case starlark.Int:
		if i, ok := t.Int64(); ok {
			return i
		}
		return t.String()
	case starlark.Float:
		return float64(t)
	default:
		return v.String()
	}
}

func stringList(items []string) *starlark.List {
	vals := make([]starlark.Value, len(items))
	for i, s := range items {
		vals[i] = starlark.String(s)
	}
	return starlark.NewList(vals)
}
