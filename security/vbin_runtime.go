package security

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
)

type governedCommand struct {
	Args      []string
	Dir       string
	Env       map[string]string
	Stdin     io.Reader
	MaxOutput int
}

type commandResult struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
}

type governedExecutor func(context.Context, governedCommand) (commandResult, error)

func (e *Engine) runGovernedCommand(ctx context.Context, sessionID string, command governedCommand, executor governedExecutor) (commandResult, error) {
	if len(command.Args) == 0 || command.Args[0] == "" {
		return commandResult{}, fmt.Errorf("adssh: child command is empty")
	}
	if err := e.gateCommand(e.restricted, command.Args, sessionID); err != nil {
		return commandResult{}, err
	}
	if vb, ok := e.Lookup(command.Args[0]); ok {
		return commandResult{}, e.DispatchVBin(ctx, vb, command.Args)
	}
	if executor == nil {
		executor = executeExternalCommand
	}
	return executor(ctx, command)
}

func executeExternalCommand(ctx context.Context, command governedCommand) (commandResult, error) {
	cmd := exec.CommandContext(ctx, command.Args[0], command.Args[1:]...)
	cmd.Dir = command.Dir
	cmd.Stdin = command.Stdin
	cmd.Env = overlayEnvironment(os.Environ(), command.Env)

	limit := command.MaxOutput
	if limit <= 0 {
		limit = 4 << 20
	}
	stdout := &limitedBuffer{limit: limit}
	stderr := &limitedBuffer{limit: limit}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	result := commandResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		result.ExitCode = exitErr.ExitCode()
	} else if err != nil {
		return result, err
	}
	return result, nil
}

type limitedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	remaining := b.limit - b.buffer.Len()
	if remaining <= 0 {
		return original, nil
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	_, _ = b.buffer.Write(p)
	return original, nil
}

func (b *limitedBuffer) Bytes() []byte { return append([]byte(nil), b.buffer.Bytes()...) }

func overlayEnvironment(base []string, overlay map[string]string) []string {
	if len(overlay) == 0 {
		return append([]string(nil), base...)
	}
	out := make([]string, 0, len(base)+len(overlay))
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := overlay[key]; !replaced {
			out = append(out, entry)
		}
	}
	keys := make([]string, 0, len(overlay))
	for key := range overlay {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out = append(out, key+"="+overlay[key])
	}
	return out
}
