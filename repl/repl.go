package repl

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"adssh/parser"
	"adssh/security"
	"adssh/starlarkext"
	"adssh/sys"

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
			val = "RESOLVED_SECRET_" + strings.TrimPrefix(val, "vault://")
		}
		return expand.Variable{Set: true, Kind: expand.String, Str: val}
	}
	// 2. Check Starlark globals
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

// needsContinuation reports whether buf is an incomplete Starlark expression:
// unclosed brackets/parens/braces, or last non-blank line ends with ':' or '\'.
func needsContinuation(buf string) bool {
	depth := 0
	inStr := rune(0) // current string delimiter; 0 = not in string
	prev := rune(0)

	for _, r := range buf {
		if inStr != 0 {
			if r == inStr && prev != '\\' {
				inStr = 0
			}
			prev = r
			continue
		}
		switch r {
		case '"', '\'':
			inStr = r
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		}
		prev = r
	}

	if depth > 0 {
		return true
	}

	// Check last non-blank line for block opener or explicit continuation
	lines := strings.Split(buf, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		last := strings.TrimRight(lines[i], " \t")
		if last == "" {
			continue
		}
		return strings.HasSuffix(last, ":") || strings.HasSuffix(last, "\\")
	}
	return false
}

// evalStarlark executes src in the REPL context.
// It tries expression evaluation first (so results are printed), then falls
// back to statement execution (def, for, if, assignments, etc.) and merges
// any new bindings back into globals.
func evalStarlark(thread *starlark.Thread, src string, globals starlark.StringDict, errOut io.Writer) {
	// Try as expression — prints the result value
	val, err := starlark.Eval(thread, "<stdin>", src, globals)
	if err == nil {
		if val != nil && val != starlark.None {
			fmt.Println(val.String())
		}
		return
	}

	// Fall back to statement execution (def, for, if, assignments, load, etc.)
	newBindings, err2 := starlark.ExecFile(thread, "<stdin>", src, globals)
	if err2 != nil {
		fmt.Fprintf(errOut, "Starlark error: %v\n", err2)
		return
	}
	// Merge new definitions (functions, variables) back into the live globals
	for k, v := range newBindings {
		globals[k] = v
	}
}

// isBackgroundLine returns true and the stripped command if line ends with '&'.
func isBackgroundLine(line string) (string, bool) {
	trimmed := strings.TrimRight(line, " \t")
	if strings.HasSuffix(trimmed, "&") {
		return strings.TrimRight(trimmed[:len(trimmed)-1], " \t"), true
	}
	return "", false
}

// runBackground launches line as a background job and prints [N] PID XXXX.
func runBackground(line string, out io.Writer) {
	// Build a shell command via /bin/sh so that pipes and redirects work.
	cmd := exec.Command("/bin/sh", "-c", line)
	cmd.Stdout = out
	cmd.Stderr = out

	id, err := sys.NewJob(cmd)
	if err != nil {
		fmt.Fprintf(out, "bg: failed to start: %v\n", err)
		return
	}
	fmt.Fprintf(out, "[%d] %d\n", id, cmd.Process.Pid)
}

// jobControlHandler returns an ExecHandler that intercepts jobs/fg/bg/wait.
func jobControlHandler(out io.Writer) func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if len(args) == 0 {
				return next(ctx, args)
			}

			hc := interp.HandlerCtx(ctx)
			stdout := hc.Stdout
			if stdout == nil {
				stdout = out
			}

			switch args[0] {
			case "jobs":
				jobs := sys.Jobs()
				// Sort by ID for stable output.
				sort.Slice(jobs, func(i, j int) bool { return jobs[i].ID < jobs[j].ID })
				for _, j := range jobs {
					cmdStr := strings.Join(j.Args, " ")
					fmt.Fprintf(stdout, "[%d] %-8s PID %-6d %s\n", j.ID, string(j.Status), j.PID, cmdStr)
				}
				return nil

			case "fg":
				id, err := jobIDArg(args)
				if err != nil {
					return err
				}
				return sys.FgJob(id)

			case "bg":
				id, err := jobIDArg(args)
				if err != nil {
					return err
				}
				return sys.BgJob(id)

			case "wait":
				id := 0 // 0 means wait for all
				if len(args) >= 2 {
					n, err := strconv.Atoi(args[1])
					if err != nil {
						return fmt.Errorf("wait: invalid job id: %s", args[1])
					}
					id = n
				}
				return sys.WaitJob(id)
			}

			return next(ctx, args)
		}
	}
}

// jobIDArg extracts and validates a numeric job ID from args[1].
func jobIDArg(args []string) (int, error) {
	if len(args) < 2 {
		return 0, fmt.Errorf("%s: missing job id", args[0])
	}
	id, err := strconv.Atoi(args[1])
	if err != nil || id < 1 {
		return 0, fmt.Errorf("%s: invalid job id: %s", args[0], args[1])
	}
	return id, nil
}

func Start(globals starlark.StringDict, restricted bool, historyFile string, in io.ReadCloser, out io.Writer, errOut io.Writer) {
	starlarkext.SetupExtensions(globals, restricted)

	thread := &starlark.Thread{Name: "repl"}

	// Ensure history file exists with strict permissions
	if err := os.MkdirAll(filepath.Dir(historyFile), 0700); err == nil {
		if _, err := os.Stat(historyFile); os.IsNotExist(err) {
			os.WriteFile(historyFile, []byte(""), 0600)
		} else {
			os.Chmod(historyFile, 0600)
		}
	}

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

	// Welcome banner — one line, shows both modes
	fmt.Fprintf(out, "adssh  shell: ls -la | jq '.'    starlark: aws.ec2.list_instances()    vbins: list tools    exit: quit\n")

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

	envBridge := hybridEnv{globals: globals}
	runner, err := interp.New(
		interp.Env(envBridge),
		interp.StdIO(in, out, errOut),
		// Job control handler runs first, then security interceptor.
		interp.ExecHandlers(jobControlHandler(out), security.BashInterceptor(restricted, globals)),
		interp.OpenHandler(security.VirtualOpenHandler()),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating runner: %v\n", err)
		return
	}

	for {
		// Determine dynamic prompt
		prompt := "adssh> "
		if val, ok := globals["PROMPT"]; ok {
			if s, ok := val.(starlark.String); ok {
				prompt = string(s)
			}
		}
		rl.SetPrompt(prompt)

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
			buf := line

			// Collect continuation lines for multi-line constructs
			// (def/for/if blocks, unclosed brackets, explicit '\' continuation)
			for needsContinuation(buf) {
				rl.SetPrompt("...   ")
				next, nextErr := rl.Readline()
				if nextErr != nil {
					break
				}
				// Empty line signals "done" for block-style input
				if strings.TrimSpace(next) == "" {
					break
				}
				buf += "\n" + next
			}
			rl.SetPrompt(prompt)

			evalStarlark(thread, buf, globals, errOut)
		} else {
			// Strip force-shell prefix if any
			if strings.HasPrefix(line, "!") {
				line = strings.TrimSpace(line[1:])
			} else if strings.HasPrefix(line, "$ ") {
				line = strings.TrimSpace(line[2:])
			}

			// Background execution: command ending with '&'
			if bgCmd, isBg := isBackgroundLine(line); isBg {
				runBackground(bgCmd, out)
				continue
			}

			parserFile, err := syntax.NewParser().Parse(strings.NewReader(line), "")
			if err != nil {
				fmt.Fprintf(errOut, "Parse error: %v\n", err)
				continue
			}

			ctx := context.Background()
			if val, ok := globals["SESSION_ID"]; ok {
				if sessionIDStr, ok := val.(starlark.String); ok {
					if session := sys.GetSession(string(sessionIDStr)); session != nil {
						var cancel context.CancelFunc
						ctx, cancel = context.WithCancel(context.Background())
						session.SetContext(ctx, cancel)
					}
				}
			}

			err = runner.Run(ctx, parserFile)

			if val, ok := globals["SESSION_ID"]; ok {
				if sessionIDStr, ok := val.(starlark.String); ok {
					if session := sys.GetSession(string(sessionIDStr)); session != nil {
						session.SetContext(context.Background(), nil)
					}
				}
			}
			if err != nil {
				if err != context.Canceled && !strings.Contains(err.Error(), "context canceled") {
					fmt.Fprintf(errOut, "Command error: %v\n", err)
				}
			}
		}
	}
}
