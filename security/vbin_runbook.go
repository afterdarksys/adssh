package security

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/afterdarksys/adssh/internal/config"
	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
)

type runbookBinary struct{}

func (runbookBinary) Name() string { return "runbook" }
func (runbookBinary) Description() string {
	return "Discover and execute typed Starlark runbooks through governance checkpoints"
}
func (runbookBinary) Usage() string {
	return "runbook <list|show NAME|run NAME [--param key=value] [--dry-run]>"
}

type runbookDefinition struct {
	Name        string
	Description string
	Params      map[string]runbookParam
	Steps       []runbookStep
}

type runbookParam struct {
	Type        string
	Required    bool
	Default     string
	HasDefault  bool
	Description string
}

type runbookStep struct {
	Name    string
	Command []string
}

func (runbookBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	if len(args) < 2 {
		return fmt.Errorf("runbook: usage: %s", runbookBinary{}.Usage())
	}
	switch args[1] {
	case "list":
		names, err := listRunbooks()
		if err != nil {
			return err
		}
		for _, name := range names {
			definition, err := loadRunbook(name)
			if err != nil {
				fmt.Fprintf(hc.Stdout, "%-24s ERROR: %v\n", name, err)
				continue
			}
			fmt.Fprintf(hc.Stdout, "%-24s %s\n", name, definition.Description)
		}
		return nil
	case "show":
		if len(args) != 3 {
			return fmt.Errorf("runbook show: usage: runbook show NAME")
		}
		definition, err := loadRunbook(args[2])
		if err != nil {
			return err
		}
		printRunbook(hc, definition)
		return nil
	case "run":
		return runRunbook(ctx, hc, args[2:])
	default:
		return fmt.Errorf("runbook: unknown subcommand %q", args[1])
	}
}

func runRunbook(ctx context.Context, hc interp.HandlerContext, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("runbook run: a runbook name is required")
	}
	name := args[0]
	dryRun := false
	rawParams := map[string]string{}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--dry-run":
			dryRun = true
		case "--param", "-p":
			if i+1 >= len(args) {
				return fmt.Errorf("runbook run: --param requires key=value")
			}
			i++
			key, value, found := strings.Cut(args[i], "=")
			if !found || key == "" {
				return fmt.Errorf("runbook run: parameter must be key=value")
			}
			rawParams[key] = value
		default:
			return fmt.Errorf("runbook run: unknown option %q", args[i])
		}
	}
	definition, err := loadRunbook(name)
	if err != nil {
		return err
	}
	params, err := resolveRunbookParams(definition, rawParams)
	if err != nil {
		return err
	}
	steps := interpolateRunbookSteps(definition.Steps, params)
	engine := engineFromContext(ctx)
	sessionID := SessionIDFromContext(ctx)
	for index, step := range steps {
		if dryRun {
			explanation, err := engine.ExplainCommand(sessionID, step.Command)
			if err != nil {
				return err
			}
			fmt.Fprintf(hc.Stdout, "DRY-RUN %d/%d %-18s %s · %s\n", index+1, len(steps), step.Name, strings.Join(step.Command, " "), explanation.Outcome)
			continue
		}
		fmt.Fprintf(hc.Stdout, "RUN %d/%d %s\n", index+1, len(steps), step.Name)
		result, err := engine.runGovernedCommand(ctx, sessionID, governedCommand{
			Args:  step.Command,
			Dir:   hc.Dir,
			Stdin: hc.Stdin,
		}, nil)
		if len(result.Stdout) > 0 {
			_, _ = hc.Stdout.Write(result.Stdout)
		}
		if len(result.Stderr) > 0 {
			_, _ = hc.Stderr.Write(result.Stderr)
		}
		if err != nil {
			return fmt.Errorf("runbook %s step %q: %w", name, step.Name, err)
		}
		if result.ExitCode != 0 {
			return fmt.Errorf("runbook %s step %q exited with status %d", name, step.Name, result.ExitCode)
		}
	}
	return nil
}

func runbookDir() string {
	if path := os.Getenv("ADSSH_RUNBOOK_DIR"); path != "" {
		return path
	}
	return filepath.Join(config.XDGConfigHome(), "runbooks")
}

func listRunbooks() ([]string, error) {
	entries, err := os.ReadDir(runbookDir())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("runbook: list directory: %w", err)
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".star") {
			continue
		}
		names = append(names, strings.TrimSuffix(entry.Name(), ".star"))
	}
	sort.Strings(names)
	return names, nil
}

func validRunbookName(name string) bool {
	if name == "" || filepath.Base(name) != name {
		return false
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func loadRunbook(name string) (runbookDefinition, error) {
	if !validRunbookName(name) {
		return runbookDefinition{}, fmt.Errorf("runbook: invalid name %q", name)
	}
	path := filepath.Join(runbookDir(), name+".star")
	info, err := os.Lstat(path)
	if err != nil {
		return runbookDefinition{}, fmt.Errorf("runbook: open %s: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return runbookDefinition{}, fmt.Errorf("runbook: %s must be a regular file", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return runbookDefinition{}, fmt.Errorf("runbook: %s must not be group/world writable", path)
	}
	thread := &starlark.Thread{Name: "runbook-load"}
	thread.SetMaxExecutionSteps(1_000_000)
	globals, err := starlark.ExecFile(thread, path, nil, nil)
	if err != nil {
		return runbookDefinition{}, fmt.Errorf("runbook: load %s: %w", name, err)
	}
	definition := runbookDefinition{Name: name, Params: map[string]runbookParam{}}
	if value, ok := globals["description"]; ok {
		description, ok := starlark.AsString(value)
		if !ok {
			return definition, fmt.Errorf("runbook: description must be a string")
		}
		definition.Description = description
	}
	if value, ok := globals["params"]; ok {
		params, ok := value.(*starlark.Dict)
		if !ok {
			return definition, fmt.Errorf("runbook: params must be a dict")
		}
		for _, item := range params.Items() {
			paramName, ok := starlark.AsString(item[0])
			if !ok || !validParamName(paramName) {
				return definition, fmt.Errorf("runbook: invalid parameter name")
			}
			spec, ok := item[1].(*starlark.Dict)
			if !ok {
				return definition, fmt.Errorf("runbook: parameter %s spec must be a dict", paramName)
			}
			parsed, err := parseRunbookParam(spec)
			if err != nil {
				return definition, fmt.Errorf("runbook: parameter %s: %w", paramName, err)
			}
			definition.Params[paramName] = parsed
		}
	}
	value, ok := globals["steps"]
	if !ok {
		return definition, fmt.Errorf("runbook: steps is required")
	}
	steps, ok := value.(*starlark.List)
	if !ok || steps.Len() == 0 {
		return definition, fmt.Errorf("runbook: steps must be a non-empty list")
	}
	for i := 0; i < steps.Len(); i++ {
		step, err := parseRunbookStep(i+1, steps.Index(i))
		if err != nil {
			return definition, err
		}
		definition.Steps = append(definition.Steps, step)
	}
	return definition, nil
}

func parseRunbookParam(spec *starlark.Dict) (runbookParam, error) {
	param := runbookParam{Type: "string"}
	if value, found, _ := spec.Get(starlark.String("type")); found {
		kind, ok := starlark.AsString(value)
		if !ok || (kind != "string" && kind != "int" && kind != "float" && kind != "bool") {
			return param, fmt.Errorf("type must be string, int, float, or bool")
		}
		param.Type = kind
	}
	if value, found, _ := spec.Get(starlark.String("required")); found {
		required, ok := value.(starlark.Bool)
		if !ok {
			return param, fmt.Errorf("required must be boolean")
		}
		param.Required = bool(required)
	}
	if value, found, _ := spec.Get(starlark.String("description")); found {
		description, ok := starlark.AsString(value)
		if !ok {
			return param, fmt.Errorf("description must be string")
		}
		param.Description = description
	}
	if value, found, _ := spec.Get(starlark.String("default")); found {
		param.Default = starlarkScalarString(value)
		param.HasDefault = true
	}
	return param, nil
}

func parseRunbookStep(index int, value starlark.Value) (runbookStep, error) {
	spec, ok := value.(*starlark.Dict)
	if !ok {
		return runbookStep{}, fmt.Errorf("runbook: step %d must be a dict", index)
	}
	step := runbookStep{Name: fmt.Sprintf("step-%d", index)}
	if value, found, _ := spec.Get(starlark.String("name")); found {
		name, ok := starlark.AsString(value)
		if !ok || name == "" {
			return step, fmt.Errorf("runbook: step %d name must be a non-empty string", index)
		}
		step.Name = name
	}
	value, found, _ := spec.Get(starlark.String("command"))
	command, ok := value.(*starlark.List)
	if !found || !ok || command.Len() == 0 {
		return step, fmt.Errorf("runbook: step %d command must be a non-empty argv list", index)
	}
	for i := 0; i < command.Len(); i++ {
		arg, ok := starlark.AsString(command.Index(i))
		if !ok {
			return step, fmt.Errorf("runbook: step %d command arguments must be strings", index)
		}
		step.Command = append(step.Command, arg)
	}
	return step, nil
}

func resolveRunbookParams(definition runbookDefinition, raw map[string]string) (map[string]string, error) {
	for key := range raw {
		if _, ok := definition.Params[key]; !ok {
			return nil, fmt.Errorf("runbook %s: unknown parameter %q", definition.Name, key)
		}
	}
	resolved := map[string]string{}
	for name, spec := range definition.Params {
		value, supplied := raw[name]
		if !supplied && spec.HasDefault {
			value, supplied = spec.Default, true
		}
		if !supplied {
			if spec.Required {
				return nil, fmt.Errorf("runbook %s: required parameter %q is missing", definition.Name, name)
			}
			continue
		}
		if err := validateRunbookParam(spec.Type, value); err != nil {
			return nil, fmt.Errorf("runbook %s: parameter %q: %w", definition.Name, name, err)
		}
		resolved[name] = value
	}
	return resolved, nil
}

func validateRunbookParam(kind, value string) error {
	switch kind {
	case "string":
		return nil
	case "int":
		if _, err := strconv.ParseInt(value, 10, 64); err != nil {
			return fmt.Errorf("must be an integer")
		}
	case "float":
		if _, err := strconv.ParseFloat(value, 64); err != nil {
			return fmt.Errorf("must be a number")
		}
	case "bool":
		if _, err := strconv.ParseBool(value); err != nil {
			return fmt.Errorf("must be a boolean")
		}
	}
	return nil
}

func interpolateRunbookSteps(steps []runbookStep, params map[string]string) []runbookStep {
	out := make([]runbookStep, len(steps))
	for i, step := range steps {
		out[i] = runbookStep{Name: step.Name, Command: make([]string, len(step.Command))}
		for j, arg := range step.Command {
			for name, value := range params {
				arg = strings.ReplaceAll(arg, "${"+name+"}", value)
			}
			out[i].Command[j] = arg
		}
	}
	return out
}

func printRunbook(hc interp.HandlerContext, definition runbookDefinition) {
	fmt.Fprintf(hc.Stdout, "%s — %s\n", definition.Name, definition.Description)
	names := make([]string, 0, len(definition.Params))
	for name := range definition.Params {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		spec := definition.Params[name]
		fmt.Fprintf(hc.Stdout, "  param %-16s type=%s required=%t", name, spec.Type, spec.Required)
		if spec.HasDefault {
			fmt.Fprintf(hc.Stdout, " default=%s", spec.Default)
		}
		fmt.Fprintln(hc.Stdout)
	}
	for i, step := range definition.Steps {
		fmt.Fprintf(hc.Stdout, "  step %d %-16s %s\n", i+1, step.Name, strings.Join(step.Command, " "))
	}
}

func validParamName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

func starlarkScalarString(value starlark.Value) string {
	if text, ok := starlark.AsString(value); ok {
		return text
	}
	return value.String()
}
