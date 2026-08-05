package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
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
admin evidence [--session id] [--change id] [--since time] [--until time] [--out path]
admin serve --listen addr [--api-key key|--api-key-env name]`
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
	case "serve":
		return adminServe(ctx, args[2:])
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
	sessions := adminGatewaySnapshot()
	if jsonOutput {
		encoder := json.NewEncoder(hc.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(sessions)
	}
	fmt.Fprintln(hc.Stdout, "admin: gateways")
	for _, s := range sessions {
		started, _ := s["started_at"].(time.Time)
		fmt.Fprintf(hc.Stdout, "  %s listen=%s target=%s user=%s age=%s",
			s["id"], s["listen"], s["target"], emptyDash(fmt.Sprint(s["user"])), formatSessionDuration(time.Since(started)))
		if name := fmt.Sprint(s["name"]); name != "" {
			fmt.Fprintf(hc.Stdout, " name=%q", name)
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

func adminServe(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	listen := "127.0.0.1:8787"
	apiKey := os.Getenv("ADSSH_ADMIN_API_KEY")
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--listen":
			i++
			if i >= len(args) {
				return fmt.Errorf("admin serve: --listen requires a value")
			}
			listen = args[i]
		case "--api-key":
			i++
			if i >= len(args) {
				return fmt.Errorf("admin serve: --api-key requires a value")
			}
			apiKey = args[i]
		case "--api-key-env":
			i++
			if i >= len(args) {
				return fmt.Errorf("admin serve: --api-key-env requires a value")
			}
			apiKey = os.Getenv(args[i])
		default:
			return fmt.Errorf("admin serve: unknown option %q", args[i])
		}
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("admin serve: listen: %w", err)
	}
	defer listener.Close()

	actual := listener.Addr().String()
	engine := engineFromContext(ctx)
	engine.LogEvent(fmt.Sprintf("ADMIN_HTTP_START: listen=%s auth=%t", actual, apiKey != ""))
	fmt.Fprintln(hc.Stdout, formatAdminHTTPStart(actual, apiKey))
	server := adminHTTPServerTimeouts(NewAdminHTTPHandler(engine, apiKey))
	errCh := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		return err
	}
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
