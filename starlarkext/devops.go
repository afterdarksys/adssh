package starlarkext

import (
	"fmt"
	"github.com/afterdarksys/adssh/devops"
	"go.starlark.net/starlark"
)

func builtinCloudGen(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var provider, resource, action string
	var kwArgsDict *starlark.Dict

	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "provider", &provider, "resource", &resource, "action", &action, "args?", &kwArgsDict); err != nil {
		return nil, err
	}

	goArgs := make(map[string]string)
	if kwArgsDict != nil {
		for _, item := range kwArgsDict.Items() {
			k, ok1 := item[0].(starlark.String)
			if !ok1 {
				return nil, fmt.Errorf("cloud.gen: kwargs dict must have string keys")
			}

			// Try to handle strings and ints
			switch v := item[1].(type) {
			case starlark.String:
				goArgs[string(k)] = string(v)
			case starlark.Int:
				goArgs[string(k)] = v.String()
			case starlark.Bool:
				if v {
					goArgs[string(k)] = "true"
				} else {
					goArgs[string(k)] = "false"
				}
			default:
				goArgs[string(k)] = v.String()
			}
		}
	}

	cmdStr, err := devops.GenerateCommand(provider, resource, action, goArgs)
	if err != nil {
		return nil, err
	}

	return starlark.String(cmdStr), nil
}

func builtinRegisterMapper(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var provider string
	var callable starlark.Callable

	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "provider", &provider, "callable", &callable); err != nil {
		return nil, err
	}

	mapperFn := func(resource, action string, args map[string]string) (string, error) {
		newThread := &starlark.Thread{Name: "mapper-" + provider}

		starlarkArgs := starlark.NewDict(len(args))
		for k, v := range args {
			_ = starlarkArgs.SetKey(starlark.String(k), starlark.String(v))
		}

		res, err := starlark.Call(newThread, callable, starlark.Tuple{
			starlark.String(resource),
			starlark.String(action),
			starlarkArgs,
		}, nil)
		if err != nil {
			return "", err
		}

		if str, ok := res.(starlark.String); ok {
			return string(str), nil
		}
		return "", fmt.Errorf("mapper for %s must return a string", provider)
	}

	devops.RegisterMapper(provider, mapperFn)
	return starlark.None, nil
}
