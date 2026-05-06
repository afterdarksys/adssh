package security

import (
	"adssh/devops"
	"context"
	"fmt"
	"mvdan.cc/sh/v3/interp"
	"strings"
)

func runCmdGen(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)

	if len(args) < 4 {
		return fmt.Errorf("usage: cmdgen <provider> <resource> <action> [key=value...]")
	}

	provider := args[1]
	resource := args[2]
	action := args[3]

	kvArgs := make(map[string]string)
	for _, kv := range args[4:] {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) == 2 {
			kvArgs[parts[0]] = parts[1]
		}
	}

	cmdStr, err := devops.GenerateCommand(provider, resource, action, kvArgs)
	if err != nil {
		return err
	}

	fmt.Fprintf(hc.Stdout, "Generated Command: %s\n", cmdStr)

	// Wait, we should probably actually execute it!
	// But `interp.HandlerCtx` doesn't have an easy way to inject it back into the parser from here easily
	// since we are mid-execution.
	// For this prototype, printing the exact command is the safest way to act as an abstraction engine,
	// or the user can `eval $(cmdgen aws ec2 create...)`
	fmt.Fprintf(hc.Stdout, "To execute, run: eval $(cmdgen %s)\n", strings.Join(args[1:], " "))
	return nil
}
