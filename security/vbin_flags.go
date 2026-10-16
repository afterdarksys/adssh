package security

import (
	"fmt"
	"strings"
)

func splitDashDash(args []string) (head, rest []string) {
	for i, arg := range args {
		if arg == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

func parseNamedFlags(command string, args []string, valued map[string]bool) (map[string]string, error) {
	out := make(map[string]string)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") || len(arg) < 3 {
			return nil, fmt.Errorf("%s: unknown option %q", command, arg)
		}
		name := arg[2:]
		takes, ok := valued[name]
		if !ok {
			return nil, fmt.Errorf("%s: unknown option %q", command, arg)
		}
		if _, exists := out[name]; exists {
			return nil, fmt.Errorf("%s: unknown option %q", command, arg)
		}
		if !takes {
			out[name] = ""
			continue
		}
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
			return nil, fmt.Errorf("%s: %s requires a value", command, arg)
		}
		i++
		out[name] = args[i]
	}
	return out, nil
}

func requiredFlag(command string, flags map[string]string, name string) (string, error) {
	value, ok := flags[name]
	if !ok || value == "" {
		return "", fmt.Errorf("%s: --%s is required", command, name)
	}
	return value, nil
}
