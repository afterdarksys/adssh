package starlarkext

// Extended regex helpers for Starlark, appended to the `re` namespace created in
// SetupExtensions (which already provides re.match / re.pcre_match). These use
// Go's RE2 engine (regexp), so patterns are linear-time and safe against
// catastrophic backtracking. All are pure and classified into the `regex`
// capability group.

import (
	"fmt"
	"regexp"

	"go.starlark.net/starlark"
)

// SetupRegexExtAPI adds find/findall/replace/split onto the existing `re` dict.
// It MUST run after the re dict is created in SetupExtensions; if the dict is
// missing it is created defensively.
func SetupRegexExtAPI(env starlark.StringDict) {
	d, ok := env["re"].(*starlark.Dict)
	if !ok {
		d = starlark.NewDict(6)
		env["re"] = d
	}
	_ = d.SetKey(starlark.String("find"), starlark.NewBuiltin("find", reFind))
	_ = d.SetKey(starlark.String("findall"), starlark.NewBuiltin("findall", reFindAll))
	_ = d.SetKey(starlark.String("replace"), starlark.NewBuiltin("replace", reReplace))
	_ = d.SetKey(starlark.String("split"), starlark.NewBuiltin("split", reSplit))
}

// re.find(pattern, text) -> the first match string, or None if no match. When
// the pattern has capture groups, returns a list [full, g1, g2, ...] instead.
func reFind(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	re, text, err := compileArgs(b, args, kwargs)
	if err != nil {
		return nil, err
	}
	m := re.FindStringSubmatch(text)
	if m == nil {
		return starlark.None, nil
	}
	if re.NumSubexp() == 0 {
		return starlark.String(m[0]), nil
	}
	return stringList(m), nil
}

// re.findall(pattern, text) -> list of all non-overlapping match strings.
func reFindAll(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	re, text, err := compileArgs(b, args, kwargs)
	if err != nil {
		return nil, err
	}
	return stringList(re.FindAllString(text, -1)), nil
}

// re.replace(pattern, text, repl) -> text with every match replaced. repl may
// use $1 / ${name} expansion (Go regexp semantics).
func reReplace(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pattern, text, repl string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "pattern", &pattern, "text", &text, "repl", &repl); err != nil {
		return nil, err
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("re.replace: %v", err)
	}
	return starlark.String(re.ReplaceAllString(text, repl)), nil
}

// re.split(pattern, text) -> list of substrings split around every match.
func reSplit(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	re, text, err := compileArgs(b, args, kwargs)
	if err != nil {
		return nil, err
	}
	return stringList(re.Split(text, -1)), nil
}

// compileArgs unpacks (pattern, text) and compiles the RE2 pattern.
func compileArgs(b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (*regexp.Regexp, string, error) {
	var pattern, text string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "pattern", &pattern, "text", &text); err != nil {
		return nil, "", err
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, "", fmt.Errorf("re.%s: %v", b.Name(), err)
	}
	return re, text, nil
}
