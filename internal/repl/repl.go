package repl

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/afterdarksys/adssh/internal/starlarkext"
	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/afterdarksys/adssh/parser"
	"github.com/afterdarksys/adssh/security"

	"github.com/chzyer/readline"
	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
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
func evalStarlark(thread *starlark.Thread, src string, globals starlark.StringDict, errOut io.Writer) int {
	// Try as expression — prints the result value
	val, err := starlark.Eval(thread, "<stdin>", src, globals)
	if err == nil {
		if val != nil && val != starlark.None {
			fmt.Println(val.String())
		}
		return 0
	}

	// Fall back to statement execution (def, for, if, assignments, load, etc.)
	newBindings, err2 := starlark.ExecFile(thread, "<stdin>", src, globals)
	if err2 != nil {
		fmt.Fprintf(errOut, "Starlark error: %v\n", err2)
		return 1
	}
	// Merge new definitions (functions, variables) back into the live globals
	for k, v := range newBindings {
		globals[k] = v
	}
	return 0
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

// expandPrompt expands bash/zsh-style prompt escape sequences. cwd is the
// session's current working directory (the runner's Dir), so per-session
// prompts reflect each session's own cwd rather than the process cwd.
func expandPrompt(template string, globals starlark.StringDict, thread *starlark.Thread, cwd string) string {
	home, _ := os.UserHomeDir()

	hostname, _ := os.Hostname()
	shortHost := hostname
	if idx := strings.Index(hostname, "."); idx >= 0 {
		shortHost = hostname[:idx]
	}

	uid := os.Getuid()
	promptChar := "$"
	if uid == 0 {
		promptChar = "#"
	}

	username := ""
	if u, err := user.Current(); err == nil {
		username = u.Username
	}

	cwdDisplay := cwd
	if home != "" && strings.HasPrefix(cwd, home) {
		cwdDisplay = "~" + cwd[len(home):]
	}

	var result strings.Builder
	i := 0
	for i < len(template) {
		// $(expr) — Starlark eval
		if template[i] == '$' && i+1 < len(template) && template[i+1] == '(' {
			end := strings.Index(template[i+2:], ")")
			if end >= 0 {
				expr := template[i+2 : i+2+end]
				val, err := starlark.Eval(thread, "<prompt>", expr, globals)
				if err == nil {
					result.WriteString(val.String())
				}
				i = i + 2 + end + 1
				continue
			}
		}
		// %~ (zsh style) → same as \w
		if template[i] == '%' && i+1 < len(template) && template[i+1] == '~' {
			result.WriteString(cwdDisplay)
			i += 2
			continue
		}
		if template[i] == '\\' && i+1 < len(template) {
			switch template[i+1] {
			case 'w':
				result.WriteString(cwdDisplay)
			case 'W':
				result.WriteString(filepath.Base(cwd))
			case 'u':
				result.WriteString(username)
			case 'h':
				result.WriteString(shortHost)
			case 'H':
				result.WriteString(hostname)
			case '$':
				result.WriteString(promptChar)
			case 'n':
				result.WriteString("\n")
			case 't':
				result.WriteString(time.Now().Format("15:04:05"))
			case 'd':
				result.WriteString(time.Now().Format("Mon Jan 02"))
			case 'e':
				result.WriteString("\x1b")
			case '[', ']':
				// non-printing markers — strip
			default:
				result.WriteByte(template[i])
				result.WriteByte(template[i+1])
			}
			i += 2
			continue
		}
		result.WriteByte(template[i])
		i++
	}
	return result.String()
}

// callHook calls a Starlark callable stored in globals[key] with the given args.
func callHook(globals starlark.StringDict, key string, args starlark.Tuple) {
	fn, ok := globals[key]
	if !ok {
		return
	}
	callable, ok := fn.(starlark.Callable)
	if !ok {
		return
	}
	t := &starlark.Thread{Name: key}
	starlark.Call(t, callable, args, nil) //nolint:errcheck
}

// handleTrap processes the `trap` builtin.
func handleTrap(line string, globals starlark.StringDict, thread *starlark.Thread, runner *interp.Runner, out, errOut io.Writer, trapExit *string) {
	fields := strings.Fields(line)
	if len(fields) == 1 {
		// Print current traps.
		if td, ok := globals["__traps__"]; ok {
			if dict, ok := td.(*starlark.Dict); ok {
				for _, kv := range dict.Items() {
					fmt.Fprintf(out, "trap -- %s %s\n", kv[1], kv[0])
				}
			}
		}
		if *trapExit != "" {
			fmt.Fprintf(out, "trap -- %q EXIT\n", *trapExit)
		}
		return
	}
	if len(fields) < 3 {
		fmt.Fprintf(errOut, "trap: usage: trap 'code' SIGNAL\n")
		return
	}
	// Reassemble code (may be quoted, fields[1] is already unquoted by Fields).
	// For simplicity, take everything between first and last token as code.
	code := fields[1]
	sig := fields[len(fields)-1]

	switch sig {
	case "EXIT":
		*trapExit = code
	default:
		if _, ok := globals["__traps__"]; !ok {
			globals["__traps__"] = starlark.NewDict(8)
		}
		if dict, ok := globals["__traps__"].(*starlark.Dict); ok {
			dict.SetKey(starlark.String(sig), starlark.String(code)) //nolint:errcheck
		}
	}
}

func Start(globals starlark.StringDict, restricted bool, historyFile string, in io.ReadCloser, out io.Writer, errOut io.Writer) {
	// 4d. $SHLVL
	shlvl := 1
	if s := os.Getenv("SHLVL"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			shlvl = n + 1
		}
	}
	os.Setenv("SHLVL", strconv.Itoa(shlvl))
	globals["SHLVL"] = starlark.MakeInt(shlvl)

	// Task 5: ensure __aliases__ is initialized.
	if _, ok := globals["__aliases__"]; !ok {
		globals["__aliases__"] = starlark.NewDict(16)
	}

	starlarkext.SetupExtensions(starlarkext.ExtensionOptions{Env: globals, Restricted: restricted})

	// Per-invocation directory stack: each Start (one per SSH session, one per
	// single-user REPL) gets its own stack so concurrent sessions never share
	// pushd/popd/cd- state via the process-global sys.DirStack().
	dirs := &sys.DirStackState{}

	thread := &starlark.Thread{Name: "repl"}

	// Ensure history file exists with strict permissions
	if err := os.MkdirAll(filepath.Dir(historyFile), 0700); err == nil {
		if _, err := os.Stat(historyFile); os.IsNotExist(err) {
			if err := os.WriteFile(historyFile, []byte(""), 0600); err != nil {
				fmt.Fprintf(os.Stderr, "adssh: warning: could not create history file %s: %v\n", historyFile, err)
			}
		} else if err := os.Chmod(historyFile, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "adssh: warning: could not set permissions on history file %s: %v\n", historyFile, err)
		}
	}

	// 4b. Shell history slice
	shellHistory := make([]string, 0, 256)

	rl, err := readline.NewEx(&readline.Config{
		Prompt:            "adssh> ",
		HistoryFile:       historyFile,
		InterruptPrompt:   "^C",
		EOFPrompt:         "exit",
		HistorySearchFold: true,
		AutoComplete:      &adsshCompleter{globals: globals},
		Listener:          newAdsshListener(&shellHistory),
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

	// commandRunning is true while runner.Run() is executing a foreground command.
	// The SIGTSTP handler uses this to decide whether to suspend adssh itself.
	var commandRunning atomic.Bool

	// SIGTSTP handler: when at the prompt (no foreground command), suspend adssh
	// by restoring the terminal to a sane state, raising SIGSTOP on ourselves,
	// then re-entering raw mode when SIGCONT wakes us.
	tstpCh := make(chan os.Signal, 1)
	signal.Notify(tstpCh, syscall.SIGTSTP)
	go func() {
		for range tstpCh {
			if commandRunning.Load() {
				// A foreground command owns the terminal; let the signal reach it
				// by temporarily defaulting and re-raising.
				signal.Reset(syscall.SIGTSTP)
				_ = syscall.Kill(os.Getpid(), syscall.SIGTSTP)
				signal.Notify(tstpCh, syscall.SIGTSTP)
				continue
			}
			// At the prompt: save terminal state, restore cooked mode, stop self.
			saved, saveErr := sys.SaveTermios(int(os.Stdin.Fd()))
			if saveErr == nil {
				_ = sys.MakeSane(int(os.Stdin.Fd()))
			}
			rl.Clean() // erase the partial prompt line before stopping
			fmt.Fprintln(out)
			// Reset disposition so the SIGSTOP below actually suspends us.
			signal.Reset(syscall.SIGTSTP)
			_ = syscall.Kill(os.Getpid(), syscall.SIGSTOP)
			// Execution resumes here on SIGCONT.
			signal.Notify(tstpCh, syscall.SIGTSTP)
			if saveErr == nil {
				_ = sys.RestoreTermios(int(os.Stdin.Fd()), saved)
			}
			// Redraw the prompt so the user sees where they are.
			rl.SetPrompt("adssh> ")
		}
	}()

	// Register set_keymap into Starlark globals
	globals["set_keymap"] = starlark.NewBuiltin("set_keymap", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var mode string
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "mode", &mode); err != nil {
			return nil, err
		}
		switch mode {
		case "vi":
			rl.SetVimMode(true)
		case "emacs":
			rl.SetVimMode(false)
		default:
			return nil, fmt.Errorf("set_keymap: unknown mode '%s'. Use 'vi' or 'emacs'", mode)
		}
		return starlark.None, nil
	})

	envBridge := hybridEnv{globals: globals}
	sessState := &security.SessionState{Restricted: restricted, Globals: globals, Dirs: dirs}
	runner, err := interp.New(
		interp.Env(envBridge),
		interp.StdIO(in, out, errOut),
		// Job control handler runs first, then the session-aware security
		// interceptor (which uses this session's own directory stack).
		interp.CallHandler(security.CallInterceptorSession(sessState)),
		interp.ExecHandlers(jobControlHandler(out), security.BashInterceptorSession(sessState)),
		interp.OpenHandler(security.VirtualOpenHandler()),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating runner: %v\n", err)
		return
	}

	// Initialize this session's dirstack with the runner's working directory
	// (interp.New always resolves runner.Dir to the process cwd when unset).
	dirs.Init(runner.Dir)

	// 4c. REPL start time for $SECONDS
	replStart := time.Now()

	// 4n. EXIT trap variable
	trapExit := ""

	for {
		// 4c. Update $SECONDS and $RANDOM each iteration.
		globals["SECONDS"] = starlark.MakeInt(int(time.Since(replStart).Seconds()))
		globals["RANDOM"] = starlark.MakeInt(rand.Intn(32768))

		// Determine dynamic prompt
		prompt := "adssh> "
		if val, ok := globals["PROMPT"]; ok {
			if s, ok := val.(starlark.String); ok {
				prompt = expandPrompt(string(s), globals, thread, runner.Dir)
			}
		}

		// 4m. RPROMPT
		if rpVal, ok := globals["RPROMPT"]; ok {
			if rpStr, ok := rpVal.(starlark.String); ok && string(rpStr) != "" {
				rp := expandPrompt(string(rpStr), globals, thread, runner.Dir)
				if rp != "" {
					_, cols, err := sys.GetTerminalSize(int(os.Stdout.Fd()))
					if err == nil {
						rpVis := stripANSI(rp)
						rpLen := len([]rune(rpVis))
						startCol := cols - rpLen
						if startCol > 0 {
							rpLine := fmt.Sprintf("\x1b[s\x1b[%dG%s\x1b[u", startCol, rp)
							prompt = rpLine + prompt
						}
					}
				}
			}
		}

		rl.SetPrompt(prompt)

		line, err := rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				// Ctrl+C at the prompt: clear the line and re-prompt.
				fmt.Fprintln(out)
				continue
			}
			if err == io.EOF {
				// Ctrl+D on an empty line: exit the shell.
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

		// 4b. Append to shell history.
		shellHistory = append(shellHistory, line)

		// 4g. Alias expansion.
		if aliasDict, ok := globals["__aliases__"].(*starlark.Dict); ok {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				if v, found, _ := aliasDict.Get(starlark.String(parts[0])); found {
					if expansion, ok := v.(starlark.String); ok {
						line = string(expansion) + line[len(parts[0]):]
					}
				}
			}
		}

		// 4h. History expansion.
		if expanded, ok := ExpandHistory(line, shellHistory[:len(shellHistory)-1]); ok {
			fmt.Fprintln(out, expanded)
			line = expanded
		}

		// 4i. source / . builtin.
		if args := strings.Fields(line); len(args) >= 2 && (args[0] == "source" || args[0] == ".") {
			path := args[1]
			if strings.HasPrefix(path, "~/") {
				home, _ := os.UserHomeDir()
				path = home + path[1:]
			}
			data, err := os.ReadFile(path)
			if err != nil {
				fmt.Fprintf(errOut, "source: %v\n", err)
				continue
			}
			src := string(data)
			if strings.HasSuffix(path, ".adssh") || strings.HasSuffix(path, ".star") {
				newBindings, err := starlark.ExecFile(thread, path, src, globals)
				if err != nil {
					fmt.Fprintf(errOut, "source: %v\n", err)
				} else {
					for k, v := range newBindings {
						globals[k] = v
					}
				}
			} else {
				pf, err := syntax.NewParser().Parse(strings.NewReader(src), path)
				if err != nil {
					fmt.Fprintf(errOut, "source: parse: %v\n", err)
				} else if gErr := security.GateProgramSession(sessState, pf); gErr != nil {
					fmt.Fprintf(errOut, "source: %v\n", gErr)
				} else {
					runner.Run(context.Background(), pf) //nolint:errcheck
				}
			}
			continue
		}

		// 4j. autocd
		if !strings.Contains(line, " ") && !strings.HasPrefix(line, "!") {
			if info, err := os.Stat(line); err == nil && info.IsDir() {
				line = "cd " + line
			}
		}

		// 4n. trap builtin interception.
		if strings.HasPrefix(line, "trap ") || line == "trap" {
			handleTrap(line, globals, thread, runner, out, errOut, &trapExit)
			continue
		}

		mode := parser.DetermineMode(line)

		if mode == parser.ModeStarlark {
			buf := line

			// 4f. preexec hook
			callHook(globals, "__preexec__", starlark.Tuple{starlark.String(line)})

			// Collect continuation lines for multi-line constructs
			for needsContinuation(buf) {
				rl.SetPrompt("...   ")
				next, nextErr := rl.Readline()
				if nextErr != nil {
					break
				}
				if strings.TrimSpace(next) == "" {
					break
				}
				buf += "\n" + next
			}
			rl.SetPrompt(prompt)

			exitCode := evalStarlark(thread, buf, globals, errOut)
			globals["?"] = starlark.MakeInt(exitCode)

			// 4f. postcmd hook
			callHook(globals, "__postcmd__", starlark.Tuple{starlark.String(line), starlark.MakeInt(exitCode)})
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

			// 4k. cd interception (cd -, OLDPWD, dirstack)
			if fields := strings.Fields(line); len(fields) >= 1 && fields[0] == "cd" {
				target := ""
				if len(fields) == 1 {
					target, _ = os.UserHomeDir()
				} else if fields[1] == "-" {
					target = dirs.OldPwd()
					if target == "" {
						fmt.Fprintln(errOut, "cd: OLDPWD not set")
						continue
					}
					fmt.Fprintln(out, target)
				} else {
					target = fields[1]
					if strings.HasPrefix(target, "~/") {
						home, _ := os.UserHomeDir()
						target = home + target[1:]
					}
				}
				dirs.SetOldPwd(runner.Dir)
				if target != "" {
					line = "cd " + target
				}
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

			// 4f. preexec hook
			callHook(globals, "__preexec__", starlark.Tuple{starlark.String(line)})

			commandRunning.Store(true)
			// DeclClause keywords (export/readonly/declare/...) bypass the call
			// and exec handlers, so gate them via the AST pre-scan before running.
			runErr := security.GateProgramSession(sessState, parserFile)
			if runErr == nil {
				runErr = runner.Run(ctx, parserFile)
			}
			commandRunning.Store(false)

			// 4e. $? / exit code tracking
			exitCode := 0
			if runErr != nil {
				if exitErr, ok := runErr.(interp.ExitStatus); ok {
					exitCode = int(exitErr)
				} else if runErr != context.Canceled && !strings.Contains(runErr.Error(), "context canceled") {
					exitCode = 1
				}
			}
			globals["?"] = starlark.MakeInt(exitCode)

			if val, ok := globals["SESSION_ID"]; ok {
				if sessionIDStr, ok := val.(starlark.String); ok {
					if session := sys.GetSession(string(sessionIDStr)); session != nil {
						session.SetContext(context.Background(), nil)
					}
				}
			}
			if runErr != nil {
				if runErr != context.Canceled && !strings.Contains(runErr.Error(), "context canceled") {
					fmt.Fprintf(errOut, "Command error: %v\n", runErr)
				}
			}

			// 4f. postcmd hook
			callHook(globals, "__postcmd__", starlark.Tuple{starlark.String(line), starlark.MakeInt(exitCode)})
		}
	}

	// 4n. Run EXIT trap.
	if trapExit != "" {
		if pf, err := syntax.NewParser().Parse(strings.NewReader(trapExit), "trap"); err == nil {
			if gErr := security.GateProgramSession(sessState, pf); gErr != nil {
				fmt.Fprintf(errOut, "trap: %v\n", gErr)
			} else {
				runner.Run(context.Background(), pf) //nolint:errcheck
			}
		}
	}
}
