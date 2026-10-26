//go:build ee

// Threats: unit and journal are governed verbs over systemd and the
// journal. They require a session. Recovery and quarantine allow observe
// actions and a restart of only the configured agent unit. stop is refused
// on those paths. A failed audit does not call the runner. A timer line that
// says missed is logged again, and that second failure is returned raw
// without printing. Journal formatting failure prints the raw text.
// Non-goals: this file does not start a second systemd and does not give an
// agent a shell.

package security

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

var (
	unitRun    func(ctx context.Context, argv []string) (string, int, error)
	unitInvoke func([]string)
	journalRun func(ctx context.Context, argv []string) (string, int, error)
)

type unitBinary struct{}

func (unitBinary) Name() string        { return "unit" }
func (unitBinary) Description() string { return "Governed systemd unit verb" }
func (unitBinary) Usage() string {
	return "unit: usage: unit <status|restart|stop|logs|check|timers> [NAME]"
}

func (unitBinary) Run(ctx context.Context, args []string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if unitInvoke != nil {
		unitInvoke(append([]string(nil), args...))
	}
	if helpArgs(args) {
		return writeOut(ctx, unitBinary{}.Usage())
	}
	action, name, err := parseUnit(args)
	if err != nil {
		return err
	}
	if _, _, err := requireSession(ctx, "unit"); err != nil {
		return err
	}
	if (inRecover(ctx) || quarantineActive()) && !unitObserveAllowed(action, name) {
		return errors.New("unit: refused")
	}
	eng := engineFromContext(ctx)
	event := "UNIT " + action
	if name != "" {
		event += " " + name
	}
	if err := eng.LogEvent(event); err != nil {
		return fmt.Errorf("adssh: audit log failed: %w", err)
	}
	argv := unitArgv(action, name)
	run := unitRun
	if run == nil {
		run = func(ctx context.Context, argv []string) (string, int, error) {
			return runLimited(ctx, argv, observeEnv(), nil)
		}
	}
	text, code, err := run(ctx, argv)
	if err != nil {
		return errors.New("unit: unavailable")
	}
	if strings.Contains(strings.ToLower(text), "missed") {
		missed := strings.TrimSpace("UNIT_TIMER_MISSED " + name)
		if err := eng.LogEvent(missed); err != nil {
			return err
		}
	}
	if code != 0 && (action == "restart" || action == "stop") {
		if werr := writeOut(ctx, text); werr != nil {
			return werr
		}
		return fmt.Errorf("unit: exit %d", code)
	}
	return writeOut(ctx, text)
}

func parseUnit(args []string) (action, name string, err error) {
	usage := errors.New("unit: usage: unit <status|restart|stop|logs|check|timers> [NAME]")
	if len(args) < 2 {
		return "", "", usage
	}
	action = args[1]
	switch action {
	case "check", "timers":
		if len(args) != 2 {
			return "", "", usage
		}
		return action, "", nil
	case "status", "restart", "stop", "logs":
		if len(args) != 3 || !unitNamePattern.MatchString(args[2]) {
			return "", "", usage
		}
		return action, args[2], nil
	default:
		return "", "", usage
	}
}

func unitObserveAllowed(action, name string) bool {
	switch action {
	case "status", "logs", "check", "timers":
		return true
	case "restart":
		agent := os.Getenv("ADSSH_AGENT_UNIT")
		return agent != "" && name == agent && unitNamePattern.MatchString(name)
	default:
		return false
	}
}

func unitArgv(action, name string) []string {
	switch action {
	case "timers":
		return []string{"systemctl", "list-timers"}
	case "logs":
		return []string{"journalctl", "-u", name, "--no-pager", "-n", "200"}
	case "check":
		return []string{"systemd-analyze", "verify"}
	default:
		return []string{"systemctl", action, name}
	}
}

type journalBinary struct{}

func (journalBinary) Name() string        { return "journal" }
func (journalBinary) Description() string { return "Structured journal reader" }
func (journalBinary) Usage() string {
	return "journal: usage: journal [from NAME] [where PRED] [select FIELDS]"
}

func (journalBinary) Run(ctx context.Context, args []string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if helpArgs(args) {
		return writeOut(ctx, journalBinary{}.Usage())
	}
	unitName, pred, fields, err := parseJournal(args)
	if err != nil {
		return err
	}
	if _, _, err := requireSession(ctx, "journal"); err != nil {
		return err
	}
	argv := journalArgv(unitName)
	run := journalRun
	if run == nil {
		run = func(ctx context.Context, argv []string) (string, int, error) {
			return runLimited(ctx, argv, observeEnv(), nil)
		}
	}
	text, code, err := run(ctx, argv)
	if err != nil {
		return errors.New("journal: unavailable")
	}
	if code != 0 {
		return writeOut(ctx, text)
	}
	formatted, ferr := journalFormat(text, pred, fields)
	if ferr != nil {
		return writeOut(ctx, text)
	}
	return writeOut(ctx, formatted)
}

func parseJournal(args []string) (unitName, pred string, fields []string, err error) {
	usage := errors.New("journal: usage: journal [from NAME] [where PRED] [select FIELDS]")
	var gotFrom, gotWhere, gotSelect bool
	for i := 1; i < len(args); i++ {
		if i+1 >= len(args) {
			return "", "", nil, usage
		}
		switch args[i] {
		case "from":
			if gotFrom || args[i+1] == "" || !unitNamePattern.MatchString(args[i+1]) {
				return "", "", nil, usage
			}
			unitName = args[i+1]
			gotFrom = true
			i++
		case "where":
			if gotWhere || args[i+1] == "" {
				return "", "", nil, usage
			}
			pred = args[i+1]
			gotWhere = true
			i++
		case "select":
			if gotSelect || args[i+1] == "" {
				return "", "", nil, usage
			}
			parts := strings.Split(args[i+1], ",")
			for _, part := range parts {
				if strings.TrimSpace(part) == "" {
					return "", "", nil, usage
				}
				fields = append(fields, strings.TrimSpace(part))
			}
			gotSelect = true
			i++
		default:
			return "", "", nil, usage
		}
	}
	return unitName, pred, fields, nil
}

func journalArgv(unitName string) []string {
	if unitName == "" {
		return []string{"journalctl", "--output=json", "--no-pager", "-n", "200"}
	}
	return []string{"journalctl", "-u", unitName, "--output=json", "--no-pager", "-n", "200"}
}

func journalFormat(text, pred string, fields []string) (string, error) {
	var parsed bytes.Buffer
	if err := structuredFrom(strings.NewReader(text), &parsed, "jsonl", ""); err != nil {
		return "", err
	}
	cur := parsed.String()
	if pred != "" {
		var where bytes.Buffer
		if err := structuredWhere(strings.NewReader(cur), &where, pred); err != nil {
			return "", err
		}
		cur = where.String()
	}
	if len(fields) > 0 {
		var selected bytes.Buffer
		if err := structuredSelect(strings.NewReader(cur), &selected, fields); err != nil {
			return "", err
		}
		cur = selected.String()
	}
	return cur, nil
}

func init() {
	Register(unitBinary{})
	Register(journalBinary{})
}
