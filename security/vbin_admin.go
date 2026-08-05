package security

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
	"mvdan.cc/sh/v3/interp"
)

type adminBinary struct{}

func (adminBinary) Name() string { return "admin" }
func (adminBinary) Description() string {
	return "Local admin API for sessions, gateways, approvals, evidence, and explainability"
}
func (adminBinary) Usage() string {
	return `admin sessions [--json]
admin gateways [--json]
admin approvals [--json]
admin explain [--json] -- command [args...]
admin evidence [--session id] [--change id] [--since time] [--until time] [--out path]`
}

func (adminBinary) Run(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("admin: usage: %s", adminBinary{}.Usage())
	}
	switch args[1] {
	case "sessions":
		return adminSessions(ctx, args[2:])
	case "gateways":
		return adminGateways(ctx, args[2:])
	case "approvals":
		return adminApprovals(ctx, args[2:])
	case "explain":
		return adminExplain(ctx, args[2:])
	case "evidence":
		return adminEvidence(ctx, args[2:])
	default:
		return fmt.Errorf("admin: unknown command %q", args[1])
	}
}

func adminSessions(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	jsonOutput, err := parseJSONFlag("admin sessions", args)
	if err != nil {
		return err
	}
	sessions := sys.ListSessionInfo()
	if jsonOutput {
		encoder := json.NewEncoder(hc.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(sessions)
	}
	fmt.Fprintln(hc.Stdout, "admin: sessions")
	for _, s := range sessions {
		fmt.Fprintf(hc.Stdout, "  %s user=%s age=%s idle=%s",
			s.ID, emptyDash(s.User), formatSessionDuration(time.Since(s.CreatedAt)), formatSessionDuration(time.Since(s.LastActive)))
		if len(s.Principals) > 0 {
			fmt.Fprintf(hc.Stdout, " principals=%s", strings.Join(s.Principals, ","))
		}
		if s.CurrentCommand != "" {
			fmt.Fprintf(hc.Stdout, " command=%q", RedactSensitiveText(s.CurrentCommand))
		}
		if s.Recording != "" {
			fmt.Fprintf(hc.Stdout, " recording=%q", s.Recording)
		}
		if s.Elevation != nil {
			fmt.Fprintf(hc.Stdout, " elevation=%s expires=%s", s.Elevation.Role, s.Elevation.ExpiresAt.UTC().Format(time.RFC3339))
		}
		fmt.Fprintln(hc.Stdout)
	}
	return nil
}

func adminGateways(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	jsonOutput, err := parseJSONFlag("admin gateways", args)
	if err != nil {
		return err
	}
	gatewayMu.RLock()
	sessions := make([]*gatewaySession, 0, len(gatewaySessions))
	for _, session := range gatewaySessions {
		sessions = append(sessions, session)
	}
	gatewayMu.RUnlock()
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].ID < sessions[j].ID })
	if jsonOutput {
		out := make([]map[string]any, 0, len(sessions))
		for _, s := range sessions {
			out = append(out, map[string]any{
				"id":         s.ID,
				"name":       s.Name,
				"listen":     s.Listen,
				"target":     s.Target,
				"user":       s.User,
				"started_at": s.Started,
			})
		}
		encoder := json.NewEncoder(hc.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(out)
	}
	fmt.Fprintln(hc.Stdout, "admin: gateways")
	for _, s := range sessions {
		fmt.Fprintf(hc.Stdout, "  %s listen=%s target=%s user=%s age=%s",
			s.ID, s.Listen, s.Target, emptyDash(s.User), formatSessionDuration(time.Since(s.Started)))
		if s.Name != "" {
			fmt.Fprintf(hc.Stdout, " name=%q", s.Name)
		}
		fmt.Fprintln(hc.Stdout)
	}
	return nil
}

func adminApprovals(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	jsonOutput, err := parseJSONFlag("admin approvals", args)
	if err != nil {
		return err
	}
	pending, err := ListPending()
	if err != nil {
		return err
	}
	if jsonOutput {
		encoder := json.NewEncoder(hc.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(pending)
	}
	if len(pending) == 0 {
		fmt.Fprintln(hc.Stdout, "admin: no pending approvals")
		return nil
	}
	fmt.Fprintln(hc.Stdout, "admin: pending approvals")
	for _, p := range pending {
		fmt.Fprintf(hc.Stdout, "  %s requester=%s command=%q submitted=%s\n", p.Token, p.Requester, RedactSensitiveText(p.Command), p.Timestamp)
		fmt.Fprintf(hc.Stdout, "    approve: 4eyes approve %s\n", p.Token)
		fmt.Fprintf(hc.Stdout, "    deny:    4eyes deny %s\n", p.Token)
	}
	return nil
}

func adminExplain(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	jsonOutput := false
	var command []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			jsonOutput = true
		case "--":
			command = append(command, args[i+1:]...)
			i = len(args)
		default:
			if strings.HasPrefix(args[i], "-") && len(command) == 0 {
				return fmt.Errorf("admin explain: unknown option %q", args[i])
			}
			command = append(command, args[i])
		}
	}
	if len(command) == 0 {
		return fmt.Errorf("admin explain: usage: admin explain [--json] -- command [args...]")
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

func adminEvidence(ctx context.Context, args []string) error {
	filter := EvidenceFilter{}
	outputPath := ""
	for i := 0; i < len(args); i++ {
		var target *string
		switch args[i] {
		case "--session":
			target = &filter.SessionID
		case "--change":
			target = &filter.ChangeID
		case "--since":
			target = &filter.Since
		case "--until":
			target = &filter.Until
		case "--out":
			target = &outputPath
		default:
			return fmt.Errorf("admin evidence: unknown option %q", args[i])
		}
		if i+1 >= len(args) {
			return fmt.Errorf("admin evidence: %s requires a value", args[i])
		}
		i++
		*target = args[i]
	}
	return (evidenceBinary{}).write(ctx, engineFromContext(ctx), filter, outputPath)
}

func parseJSONFlag(name string, args []string) (bool, error) {
	jsonOutput := false
	for _, arg := range args {
		if arg == "--json" {
			jsonOutput = true
			continue
		}
		return false, fmt.Errorf("%s: unknown option %q", name, arg)
	}
	return jsonOutput, nil
}

func init() { Register(adminBinary{}) }
