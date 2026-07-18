package security

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/afterdarksys/adssh/internal/vbinui"
	"golang.org/x/term"
	"mvdan.cc/sh/v3/interp"
)

type navBinary struct{}

func (navBinary) Name() string { return "nav" }
func (navBinary) Description() string {
	return "Interactive three-column file navigator with previews and fuzzy selection"
}
func (navBinary) Usage() string {
	return "nav [path] [--hidden] [--json] [--select query] [--non-interactive]"
}

func (navBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	root := "."
	showHidden := false
	jsonOutput := false
	nonInteractive := false
	query := ""
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--hidden", "-a":
			showHidden = true
		case "--json":
			jsonOutput = true
			nonInteractive = true
		case "--non-interactive":
			nonInteractive = true
		case "--select", "-q":
			if i+1 >= len(args) {
				return fmt.Errorf("nav: --select requires a query")
			}
			i++
			query = args[i]
		case "--":
			if i+1 < len(args) {
				root = args[i+1]
			}
			i = len(args)
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("nav: unknown option %q", args[i])
			}
			root = args[i]
		}
	}
	if !filepath.IsAbs(root) {
		root = filepath.Join(hc.Dir, root)
	}
	root = filepath.Clean(root)

	if jsonOutput {
		entries, err := vbinui.ListDirectory(root, showHidden)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(hc.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(entries)
	}

	if !nonInteractive {
		file, ok := hc.Stdin.(*os.File)
		nonInteractive = !ok || !term.IsTerminal(int(file.Fd()))
	}
	selected := ""
	if nonInteractive {
		if query == "" {
			return fmt.Errorf("nav: non-interactive mode requires --select or --json")
		}
		entries, err := vbinui.ListDirectory(root, showHidden)
		if err != nil {
			return err
		}
		choices := make([]vbinui.Choice, len(entries))
		for i, entry := range entries {
			choices[i] = vbinui.Choice{Label: entry.Name, Value: entry.Path}
		}
		choice, err := vbinui.SelectChoice(choices, vbinui.SelectOptions{Query: query, NonInteractive: true})
		if err != nil {
			return err
		}
		selected = choice.Value
	} else {
		var err error
		selected, err = vbinui.Navigate(root, vbinui.NavigateOptions{ShowHidden: showHidden, Input: hc.Stdin, Output: hc.Stdout})
		if err != nil {
			return err
		}
	}

	info, err := os.Stat(selected)
	if err != nil {
		return fmt.Errorf("nav: selected path: %w", err)
	}
	if info.IsDir() {
		return hc.Builtin(ctx, []string{"cd", selected})
	}
	_, err = fmt.Fprintln(hc.Stdout, selected)
	return err
}
