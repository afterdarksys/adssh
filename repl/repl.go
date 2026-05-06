package repl

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"adssh/parser"
	"adssh/security"
	"adssh/starlarkext"

	"github.com/chzyer/readline"
	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
	"path/filepath"
)

// hybridEnv bridges os.Environ() and Starlark globals
type hybridEnv struct {
	globals starlark.StringDict
}

func (h hybridEnv) Get(name string) expand.Variable {
	// 1. Check OS
	if val, ok := os.LookupEnv(name); ok {
		if strings.HasPrefix(val, "vault://") {
			// Simulate transparent secret resolution
			val = "RESOLVED_SECRET_" + strings.TrimPrefix(val, "vault://")
		}
		return expand.Variable{Set: true, Kind: expand.String, Str: val}
	}
	// 2. Check Starlark Globals
	if val, ok := h.globals[name]; ok {
		switch v := val.(type) {
		case starlark.String:
			strVal := string(v)
			if strings.HasPrefix(strVal, "vault://") {
				strVal = "RESOLVED_SECRET_" + strings.TrimPrefix(strVal, "vault://")
			}
			return expand.Variable{Set: true, Kind: expand.String, Str: strVal}
		case starlark.Int:
			return expand.Variable{Set: true, Kind: expand.String, Str: v.String()}
		}
	}
	return expand.Variable{}
}

func (h hybridEnv) Each(fn func(name string, vr expand.Variable) bool) {
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			if !fn(parts[0], expand.Variable{Set: true, Kind: expand.String, Str: parts[1]}) {
				return
			}
		}
	}
	for k, v := range h.globals {
		switch stVal := v.(type) {
		case starlark.String:
			if !fn(k, expand.Variable{Set: true, Kind: expand.String, Str: string(stVal)}) {
				return
			}
		case starlark.Int:
			if !fn(k, expand.Variable{Set: true, Kind: expand.String, Str: stVal.String()}) {
				return
			}
		}
	}
}

func Start(globals starlark.StringDict, restricted bool, historyFile string, in io.ReadCloser, out io.Writer, errOut io.Writer) {
	// Inject standard library extensions into Starlark environment
	starlarkext.SetupExtensions(globals, restricted)

	thread := &starlark.Thread{Name: "repl"}

	// Ensure the history file exists with strict permissions
	if err := os.MkdirAll(filepath.Dir(historyFile), 0700); err == nil {
		if _, err := os.Stat(historyFile); os.IsNotExist(err) {
			os.WriteFile(historyFile, []byte(""), 0600)
		} else {
			os.Chmod(historyFile, 0600)
		}
	}

	// Initialize readline
	rl, err := readline.NewEx(&readline.Config{
		Prompt:            "adssh> ",
		HistoryFile:       historyFile,
		InterruptPrompt:   "^C",
		EOFPrompt:         "exit",
		HistorySearchFold: true,
		AutoComplete:      &adsshCompleter{globals: globals},
		Stdin:             in,
		Stdout:            out,
		Stderr:            errOut,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing readline: %v\n", err)
		return
	}
	defer rl.Close()

	// Register set_keymap into Starlark globals
	globals["set_keymap"] = starlark.NewBuiltin("set_keymap", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var mode string
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "mode", &mode); err != nil {
			return nil, err
		}
		if mode == "vi" {
			rl.SetVimMode(true)
		} else if mode == "emacs" {
			rl.SetVimMode(false)
		} else {
			return nil, fmt.Errorf("set_keymap: unknown mode '%s'. Use 'vi' or 'emacs'", mode)
		}
		return starlark.None, nil
	})

	// Instantiate persistent runner
	envBridge := hybridEnv{globals: globals}
	runner, err := interp.New(
		interp.Env(envBridge),
		interp.StdIO(in, out, errOut),
		interp.ExecHandlers(security.BashInterceptor(restricted, globals)),
		interp.OpenHandler(security.VirtualOpenHandler()),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating runner: %v\n", err)
		return
	}

	for {
		// Determine dynamic prompt
		if val, ok := globals["PROMPT"]; ok {
			if s, ok := val.(starlark.String); ok {
				rl.SetPrompt(string(s))
			}
		}

		line, err := rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt || err == io.EOF {
				break
			}
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if line == "exit" || line == "quit" {
			break
		}

		mode := parser.DetermineMode(line)

		if mode == parser.ModeStarlark {
			val, err := starlark.Eval(thread, "<stdin>", line, globals)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Starlark error: %v\n", err)
			} else if val != nil && val != starlark.None {
				fmt.Println(val.String())
			}
		} else {
			// Strip force-shell prefix if any
			if strings.HasPrefix(line, "!") {
				line = strings.TrimSpace(line[1:])
			} else if strings.HasPrefix(line, "$ ") {
				line = strings.TrimSpace(line[2:])
			}

			// Parse and execute using a robust Bash interpreter
			parserFile, err := syntax.NewParser().Parse(strings.NewReader(line), "")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Parse error: %v\n", err)
			} else {
				err = runner.Run(context.Background(), parserFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Command error: %v\n", err)
				}
			}
		}
	}
}
