package security

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/interp"
)

type whyBinary struct{}

func (whyBinary) Name() string { return "why" }
func (whyBinary) Description() string {
	return "Explain policy, RBAC, change, four-eyes, and restricted-mode decisions without executing"
}
func (whyBinary) Usage() string { return "why [--json] -- command [args...]" }

func (whyBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	jsonOutput := false
	var command []string
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--json":
			jsonOutput = true
		case "--":
			command = append(command, args[i+1:]...)
			i = len(args)
		default:
			if strings.HasPrefix(args[i], "-") && len(command) == 0 {
				return fmt.Errorf("why: unknown option %q", args[i])
			}
			command = append(command, args[i])
		}
	}
	if len(command) == 0 {
		return fmt.Errorf("why: usage: %s", whyBinary{}.Usage())
	}
	explanation, err := engineFromContext(ctx).ExplainCommand(SessionIDFromContext(ctx), command)
	if err != nil {
		return err
	}
	if jsonOutput {
		encoder := json.NewEncoder(hc.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(explanation)
	}

	printCommandExplanation(hc.Stdout, explanation)
	return nil
}
