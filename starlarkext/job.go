package starlarkext

import (
	"fmt"
	"os/exec"
	"syscall"

	"go.starlark.net/starlark"
)

// JobValue represents an asynchronous job in Starlark
type JobValue struct {
	cmd *exec.Cmd
}

func (j *JobValue) String() string {
	if j.cmd != nil && j.cmd.Process != nil {
		return fmt.Sprintf("<job pid=%d>", j.cmd.Process.Pid)
	}
	return "<job>"
}

func (j *JobValue) Type() string {
	return "job"
}

func (j *JobValue) Freeze() {}

func (j *JobValue) Truth() starlark.Bool {
	return j.cmd != nil && j.cmd.Process != nil
}

func (j *JobValue) Hash() (uint32, error) {
	if j.cmd != nil && j.cmd.Process != nil {
		return uint32(j.cmd.Process.Pid), nil
	}
	return 0, nil
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
	if j.cmd.Process == nil {
		return starlark.None, fmt.Errorf("job not started")
	}
	// Send SIGSTOP to process group
	err := syscall.Kill(-j.cmd.Process.Pid, syscall.SIGSTOP)
	if err != nil {
		return starlark.None, fmt.Errorf("failed to stop job: %v", err)
	}
	return starlark.True, nil
}

func (j *JobValue) resume(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if j.cmd.Process == nil {
		return starlark.None, fmt.Errorf("job not started")
	}
	// Send SIGCONT to process group
	err := syscall.Kill(-j.cmd.Process.Pid, syscall.SIGCONT)
	if err != nil {
		return starlark.None, fmt.Errorf("failed to resume job: %v", err)
	}
	return starlark.True, nil
}

func (j *JobValue) kill(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if j.cmd.Process == nil {
		return starlark.None, fmt.Errorf("job not started")
	}
	// Send SIGKILL to process group
	err := syscall.Kill(-j.cmd.Process.Pid, syscall.SIGKILL)
	if err != nil {
		return starlark.None, fmt.Errorf("failed to kill job: %v", err)
	}
	return starlark.True, nil
}

func (j *JobValue) wait(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if j.cmd.Process == nil {
		return starlark.None, fmt.Errorf("job not started")
	}
	err := j.cmd.Wait()
	if err != nil {
		return starlark.String(err.Error()), nil
	}
	return starlark.True, nil
}

// builtinExecAsync implements sys.exec_async
func builtinExecAsync(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var command string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "command", &command); err != nil {
		return nil, err
	}

	cmd := exec.Command("sh", "-c", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start async job: %v", err)
	}

	return &JobValue{cmd: cmd}, nil
}
