package security

import (
	"github.com/afterdarksys/adssh/devops"
	"context"
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/interp"
)

// cmdgen — DevOps command generator

type cmdgenBinary struct{}

func (cmdgenBinary) Name() string        { return "cmdgen" }
func (cmdgenBinary) Description() string { return "DevOps command generator — generate CLI commands for cloud providers" }
func (cmdgenBinary) Usage() string       { return "cmdgen <provider> <resource> <action> [key=value ...]" }

func (cmdgenBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)

	if len(args) < 4 {
		return fmt.Errorf("cmdgen: %s", cmdgenBinary{}.Usage())
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
	fmt.Fprintf(hc.Stdout, "To execute, run: eval $(cmdgen %s)\n", strings.Join(args[1:], " "))
	return nil
}

func init() { Register(cmdgenBinary{}) }
