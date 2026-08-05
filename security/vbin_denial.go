package security

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"mvdan.cc/sh/v3/interp"
)

type denialBinary struct{}

func (denialBinary) Name() string { return "??" }
func (denialBinary) Description() string {
	return "Explain the last command denial for this session"
}
func (denialBinary) Usage() string { return "?? [--json]" }

func (denialBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	jsonOutput := false
	for _, arg := range args[1:] {
		switch arg {
		case "--json":
			jsonOutput = true
		default:
			return fmt.Errorf("??: unknown option %q", arg)
		}
	}
	explanation, ok := engineFromContext(ctx).LastDenial(SessionIDFromContext(ctx))
	if !ok {
		fmt.Fprintln(hc.Stdout, "No denied command recorded for this session.")
		return nil
	}
	if jsonOutput {
		encoder := json.NewEncoder(hc.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(explanation)
	}
	printCommandExplanation(hc.Stdout, explanation)
	return nil
}

func printCommandExplanation(out io.Writer, explanation CommandExplanation) {
	fmt.Fprintf(out, "%s %s", strings.ToUpper(explanation.Outcome), explanation.Command)
	if len(explanation.Args) > 0 {
		fmt.Fprintf(out, " %s", strings.Join(explanation.Args, " "))
	}
	fmt.Fprintln(out)
	for _, stage := range explanation.Stages {
		fmt.Fprintf(out, "  %-20s %-18s", stage.Name, stage.Status)
		if stage.Reason != "" {
			fmt.Fprintf(out, " %s", stage.Reason)
		}
		fmt.Fprintln(out)
	}
	for _, step := range explanation.NextSteps {
		fmt.Fprintf(out, "  next                 %s\n", step)
	}
}

func init() { Register(denialBinary{}) }
