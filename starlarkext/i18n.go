package starlarkext

import (
	"github.com/afterdarksys/adssh/i18n"
	"fmt"

	"go.starlark.net/starlark"
)

func builtinI18nLoad(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var lang string
	var dict starlark.Dict
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "lang", &lang, "dict", &dict); err != nil {
		return nil, err
	}

	goDict := make(map[string]string)
	for _, item := range dict.Items() {
		k, ok1 := item[0].(starlark.String)
		v, ok2 := item[1].(starlark.String)
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("i18n.load: dict must contain string keys and values")
		}
		goDict[string(k)] = string(v)
	}

	i18n.Load(lang, goDict)
	return starlark.None, nil
}

func builtinI18nSetLang(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var lang string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "lang", &lang); err != nil {
		return nil, err
	}
	i18n.SetLang(lang)
	return starlark.None, nil
}

func builtinI18nT(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("i18n.T: missing key")
	}
	key, ok := args[0].(starlark.String)
	if !ok {
		return nil, fmt.Errorf("i18n.T: key must be a string")
	}

	var fmtArgs []interface{}
	for i := 1; i < len(args); i++ {
		switch v := args[i].(type) {
		case starlark.String:
			fmtArgs = append(fmtArgs, string(v))
		case starlark.Int:
			fmtArgs = append(fmtArgs, v.String())
		default:
			fmtArgs = append(fmtArgs, v.String())
		}
	}

	res := i18n.T(string(key), fmtArgs...)
	return starlark.String(res), nil
}
