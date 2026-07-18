package security

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/afterdarksys/adssh/internal/vbinui"
	"golang.org/x/term"
	"mvdan.cc/sh/v3/interp"
)

type pickBinary struct{}

func (pickBinary) Name() string { return "pick" }
func (pickBinary) Description() string {
	return "Fuzzy interactive selector for arguments, lines, or JSON choices"
}
func (pickBinary) Usage() string {
	return "pick [--query text] [--index n] [--json] [--non-interactive] [items...]"
}

func (pickBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	options := vbinui.SelectOptions{Title: "Pick", Input: hc.Stdin, Output: hc.Stdout}
	jsonInput := false
	var values []string
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--query", "-q":
			if i+1 >= len(args) {
				return fmt.Errorf("pick: --query requires a value")
			}
			i++
			options.Query = args[i]
		case "--index", "-n":
			if i+1 >= len(args) {
				return fmt.Errorf("pick: --index requires a value")
			}
			i++
			index, err := strconv.Atoi(args[i])
			if err != nil || index < 0 {
				return fmt.Errorf("pick: --index must be a non-negative integer")
			}
			options.Index = index
		case "--json":
			jsonInput = true
		case "--non-interactive":
			options.NonInteractive = true
		case "--":
			values = append(values, args[i+1:]...)
			i = len(args)
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("pick: unknown option %q", args[i])
			}
			values = append(values, args[i])
		}
	}

	choices, err := pickChoices(hc.Stdin, values, jsonInput)
	if err != nil {
		return err
	}
	if !options.NonInteractive {
		file, ok := hc.Stdin.(*os.File)
		options.NonInteractive = !ok || !term.IsTerminal(int(file.Fd()))
	}
	selected, err := vbinui.SelectChoice(choices, options)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(hc.Stdout, selected.Value)
	return err
}

func pickChoices(stdin io.Reader, values []string, jsonInput bool) ([]vbinui.Choice, error) {
	if len(values) > 0 {
		choices := make([]vbinui.Choice, len(values))
		for i, value := range values {
			choices[i] = vbinui.Choice{Label: value, Value: value}
		}
		return choices, nil
	}
	if jsonInput {
		var raw []json.RawMessage
		decoder := json.NewDecoder(io.LimitReader(stdin, 8<<20))
		if err := decoder.Decode(&raw); err != nil {
			return nil, fmt.Errorf("pick: decode JSON choices: %w", err)
		}
		choices := make([]vbinui.Choice, 0, len(raw))
		for _, item := range raw {
			var value string
			if err := json.Unmarshal(item, &value); err == nil {
				choices = append(choices, vbinui.Choice{Label: value, Value: value})
				continue
			}
			var choice vbinui.Choice
			if err := json.Unmarshal(item, &choice); err != nil || choice.Label == "" {
				return nil, fmt.Errorf("pick: JSON choices must be strings or objects with label/value")
			}
			if choice.Value == "" {
				choice.Value = choice.Label
			}
			choices = append(choices, choice)
		}
		return choices, nil
	}

	scanner := bufio.NewScanner(stdin)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var choices []vbinui.Choice
	for scanner.Scan() {
		value := scanner.Text()
		choices = append(choices, vbinui.Choice{Label: value, Value: value})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("pick: read choices: %w", err)
	}
	if len(choices) == 0 {
		return nil, fmt.Errorf("pick: no choices supplied")
	}
	return choices, nil
}
