package starlarkext

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/afterdarksys/adssh/security"

	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func createExecCmd(globals starlark.StringDict, restricted bool) func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var cmdStr string
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "cmd", &cmdStr); err != nil {
			return nil, err
		}

	parserFile, err := syntax.NewParser().Parse(strings.NewReader(cmdStr), "")
	if err != nil {
		return nil, fmt.Errorf("parse error: %v", err)
	}

	var buf bytes.Buffer
	runner, _ := interp.New(
		interp.StdIO(nil, &buf, &buf),
		interp.ExecHandlers(security.BashInterceptor(restricted, globals)),
		interp.OpenHandler(security.VirtualOpenHandler()),
	)

	err = runner.Run(context.Background(), parserFile)
	if err != nil {
		return nil, fmt.Errorf("exec error: %v, output: %s", err, buf.String())
	}

		return starlark.String(buf.String()), nil
	}
}

func createExecJSON(globals starlark.StringDict, restricted bool) func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var cmdStr string
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "cmd", &cmdStr); err != nil {
			return nil, err
		}

	parserFile, err := syntax.NewParser().Parse(strings.NewReader(cmdStr), "")
	if err != nil {
		return nil, fmt.Errorf("parse error: %v", err)
	}

	var buf bytes.Buffer
	runner, _ := interp.New(
		interp.StdIO(nil, &buf, &buf),
		interp.ExecHandlers(security.BashInterceptor(restricted, globals)),
		interp.OpenHandler(security.VirtualOpenHandler()),
	)

	err = runner.Run(context.Background(), parserFile)
	if err != nil {
		return nil, fmt.Errorf("exec error: %v, output: %s", err, buf.String())
	}

		var out interface{}
		if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
			return nil, fmt.Errorf("json parse error: %v", err)
		}

		return GoToStarlark(out), nil
	}
}
