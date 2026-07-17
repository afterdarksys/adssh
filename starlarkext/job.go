package starlarkext

import (
	"context"
	"fmt"
	"strings"

	"github.com/afterdarksys/adssh/security"

	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// JobValue represents an asynchronous job in Starlark
type JobValue struct {
	cancel   context.CancelFunc
	waitChan <-chan error
	err      error
	done     bool
}

func (j *JobValue) String() string {
	return "<job>"
}

func (j *JobValue) Type() string {
	return "job"
}

func (j *JobValue) Freeze() {}

func (j *JobValue) Truth() starlark.Bool {
	return starlark.Bool(!j.done)
}

func (j *JobValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable type: job")
}

// Attr allows accessing methods on the job object
func (j *JobValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "stop":
		return starlark.NewBuiltin("stop", j.stop), nil
	case "resume":
		return starlark.NewBuiltin("resume", j.resume), nil
	case "wait":
		return starlark.NewBuiltin("wait", j.wait), nil
	case "kill":
		return starlark.NewBuiltin("kill", j.kill), nil
	default:
		return nil, nil
	}
}

func (j *JobValue) AttrNames() []string {
	return []string{"stop", "resume", "wait", "kill"}
}

func (j *JobValue) stop(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, fmt.Errorf("stop not supported for adssh async jobs")
}

func (j *JobValue) resume(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, fmt.Errorf("resume not supported for adssh async jobs")
}

func (j *JobValue) kill(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if j.cancel != nil {
		j.cancel()
		j.done = true
	}
	return starlark.True, nil
}

func (j *JobValue) wait(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if j.done {
		if j.err != nil {
			return starlark.String(j.err.Error()), nil
		}
		return starlark.True, nil
	}
	
	j.err = <-j.waitChan
	j.done = true
	if j.err != nil {
		return starlark.String(j.err.Error()), nil
	}
	return starlark.True, nil
}

// createExecAsync implements sys.exec_async
func createExecAsync(globals starlark.StringDict, restricted bool) func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var command string
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "command", &command); err != nil {
			return nil, err
		}

		parserFile, err := syntax.NewParser().Parse(strings.NewReader(command), "")
		if err != nil {
			return nil, fmt.Errorf("parse error: %v", err)
		}

		runner, _ := interp.New(
			interp.ExecHandlers(security.BashInterceptor(restricted, globals)),
			interp.OpenHandler(security.VirtualOpenHandler()),
		)

		ctx, cancel := context.WithCancel(context.Background())
		waitChan := make(chan error, 1)

		go func() {
			waitChan <- runner.Run(ctx, parserFile)
		}()

		return &JobValue{
			cancel:   cancel,
			waitChan: waitChan,
		}, nil
	}
}
