package repl

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/afterdarksys/adssh/security"
	"github.com/afterdarksys/adssh/starlarkext"
	"github.com/afterdarksys/adssh/sys"

	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

type MenuItem struct {
	Label   string `yaml:"label"`
	Command string `yaml:"command"`
}

type MenuConfig struct {
	Title       string     `yaml:"title"`
	Description string     `yaml:"description"`
	Items       []MenuItem `yaml:"items"`
}

func StartMenu(menuPath string, globals starlark.StringDict, restricted bool, in io.ReadCloser, out io.Writer, errOut io.Writer) {
	// Read Menu YAML
	data, err := os.ReadFile(menuPath)
	if err != nil {
		fmt.Fprintf(errOut, "Error reading menu file %s: %v\n", menuPath, err)
		return
	}

	var menu MenuConfig
	if err := yaml.Unmarshal(data, &menu); err != nil {
		fmt.Fprintf(errOut, "Error parsing menu file %s: %v\n", menuPath, err)
		return
	}

	// Inject standard library extensions
	starlarkext.SetupExtensions(starlarkext.ExtensionOptions{Env: globals, Restricted: restricted})

	// Instantiate persistent runner with this session's own directory stack.
	dirs := &sys.DirStackState{}
	sessState := &security.SessionState{Restricted: restricted, Globals: globals, Dirs: dirs}
	envBridge := hybridEnv{globals: globals}
	runner, err := interp.New(
		interp.Env(envBridge),
		interp.StdIO(in, out, errOut),
		interp.CallHandler(security.CallInterceptorSession(sessState)),
		interp.ExecHandlers(security.BashInterceptorSession(sessState)),
		interp.OpenHandler(security.VirtualOpenHandler()),
	)
	if err != nil {
		fmt.Fprintf(errOut, "Error creating runner: %v\n", err)
		return
	}
	dirs.Init(runner.Dir)

	scanner := bufio.NewScanner(in)

	for {
		// Render Menu
		fmt.Fprintln(out, "\n=======================================")
		fmt.Fprintln(out, menu.Title)
		fmt.Fprintln(out, "=======================================")
		if menu.Description != "" {
			fmt.Fprintln(out, menu.Description)
		}
		for i, item := range menu.Items {
			fmt.Fprintf(out, "[%d] %s\n", i+1, item.Label)
		}
		fmt.Fprintf(out, "\nSelect an option (1-%d) or type 'exit': ", len(menu.Items))

		if !scanner.Scan() {
			break // EOF or error
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "exit" || input == "quit" {
			break
		}

		// Parse selection
		var selection int
		_, err := fmt.Sscanf(input, "%d", &selection)
		if err != nil || selection < 1 || selection > len(menu.Items) {
			fmt.Fprintln(out, "Invalid selection. Please try again.")
			continue
		}

		selectedItem := menu.Items[selection-1]
		cmdStr := selectedItem.Command

		if cmdStr == "__shell__" {
			// Optional drop to shell logic
			fmt.Fprintln(out, "Dropping to restricted shell...")
			// Start standard repl
			Start(globals, restricted, "/tmp/.adssh_history", in, out, errOut)
			continue
		}

		// Execute the command using the runner
		fmt.Fprintf(out, "\nExecuting: %s\n", selectedItem.Label)
		parserFile, err := syntax.NewParser().Parse(strings.NewReader(cmdStr), "")
		if err != nil {
			fmt.Fprintf(errOut, "Parse error: %v\n", err)
			continue
		}

		ctx := context.Background()
		if gErr := security.GateProgramSession(sessState, parserFile); gErr != nil {
			fmt.Fprintf(errOut, "Command error: %v\n", gErr)
		} else if err := runner.Run(ctx, parserFile); err != nil {
			if err != context.Canceled && !strings.Contains(err.Error(), "context canceled") {
				fmt.Fprintf(errOut, "Command error: %v\n", err)
			}
		}
		
		fmt.Fprintln(out, "\nPress Enter to return to menu...")
		scanner.Scan()
	}
}
