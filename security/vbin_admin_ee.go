//go:build ee

package security

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
admin serve [--listen 127.0.0.1:port|[::1]:port|unix:/path] [--keys-file path] [--api-key key|--api-key-env name]

--keys-file (or ADSSH_ADMIN_KEYS) names a 0600 file of name=key lines. A
named key can approve, deny, and unban as that name. The legacy
--api-key/ADSSH_ADMIN_API_KEY key can only read. --listen accepts a loopback
address or a Unix socket in a 0700 directory.`
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
	pending, err := engineFromContext(ctx).ListApprovalsPublic()
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
		id := p.RequestID
		if id == "" {
			fmt.Fprintf(hc.Stdout, "  legacy fingerprint=%s requester=%s command=%q submitted=%s\n", p.Fingerprint, p.Requester, RedactSensitiveText(p.Command), p.Timestamp)
			continue
		}
		fmt.Fprintf(hc.Stdout, "  %s requester=%s command=%q submitted=%s\n", id, p.Requester, RedactSensitiveText(p.Command), p.Timestamp)
		fmt.Fprintf(hc.Stdout, "    approve: 4eyes approve %s\n", id)
		fmt.Fprintf(hc.Stdout, "    deny:    4eyes deny %s\n", id)
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
	keysFile := os.Getenv("ADSSH_ADMIN_KEYS")
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
		case "--keys-file":
			i++
			if i >= len(args) {
				return fmt.Errorf("admin serve: --keys-file requires a value")
			}
			keysFile = args[i]
		default:
			return fmt.Errorf("admin serve: unknown option %q", args[i])
		}
	}
	var keys []AdminKey
	if keysFile != "" {
		loaded, err := LoadAdminKeysFile(keysFile)
		if err != nil {
			return fmt.Errorf("admin serve: %w", err)
		}
		keys = loaded
	}
	listener, err := adminListen(ctx, listen)
	if err != nil {
		return fmt.Errorf("admin serve: %w", err)
	}
	defer listener.Close()

	actual := listener.Addr().String()
	if listener.Addr().Network() == "unix" {
		actual = "unix:" + actual
	}
	engine := engineFromContext(ctx)
	if err := engine.LogEvent(fmt.Sprintf("ADMIN_HTTP_START: listen=%s legacy=%t keys=%s",
		actual, apiKey != "", emptyDash(adminKeyFingerprints(keys)))); err != nil {
		return fmt.Errorf("admin serve: audit: %w", err)
	}
	fmt.Fprintln(hc.Stdout, formatAdminHTTPStart(actual, apiKey, keys))
	server := adminHTTPServerTimeouts(NewAdminHTTPHandlerWithKeys(engine, apiKey, keys))
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

// adminLookupIPAddr resolves a --listen hostname. Tests replace it.
var adminLookupIPAddr = net.DefaultResolver.LookupIPAddr

// adminListen binds the admin API.
//
// Threats: the admin API carries approval and unban authority over plaintext
// HTTP, so it must not be reachable off the host. A TCP address must be a
// loopback IP, or a hostname whose every address is loopback; the listener
// binds the resolved IP literal so a later lookup cannot move it. 0.0.0.0, ::,
// an empty host, and a host with any non-loopback address are refused.
// unix:/path creates a 0600 socket in a directory that is not a symlink, is
// owned by this user, and grants no group or other access. An existing path is
// refused unless it is a socket nobody answers on. This does not stop another
// process of the same OS user from connecting; the admin key still applies.
func adminListen(ctx context.Context, spec string) (net.Listener, error) {
	if path, ok := strings.CutPrefix(spec, "unix:"); ok {
		return adminListenUnix(path)
	}
	host, port, err := net.SplitHostPort(spec)
	if err != nil {
		return nil, fmt.Errorf("listen %q: %w", spec, err)
	}
	if host == "" {
		return nil, fmt.Errorf("listen %q: host is required and must be loopback", spec)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := adminLookupIPAddr(lookupCtx, host)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("listen %q: resolve: %w", spec, err)
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("listen %q: no addresses", spec)
		}
		for _, addr := range addrs {
			if !addr.IP.IsLoopback() {
				return nil, fmt.Errorf("listen %q: %s is not loopback", spec, addr.IP)
			}
		}
		ip = addrs[0].IP
	}
	if !ip.IsLoopback() {
		return nil, fmt.Errorf("listen %q: %s is not loopback; use a loopback address or unix:/path", spec, ip)
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(ip.String(), port))
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	if tcp, ok := listener.Addr().(*net.TCPAddr); !ok || !tcp.IP.IsLoopback() {
		_ = listener.Close()
		return nil, fmt.Errorf("listen %q: bound address is not loopback", spec)
	}
	return listener, nil
}

func adminListenUnix(path string) (net.Listener, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("listen unix: path must be absolute")
	}
	path = filepath.Clean(path)
	dirInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("listen unix: %w", err)
	}
	if !dirInfo.IsDir() {
		return nil, fmt.Errorf("listen unix: parent is not a directory")
	}
	if dirInfo.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("listen unix: parent directory must be 0700")
	}
	if st, ok := dirInfo.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("listen unix: parent directory is owned by another user")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("listen unix: %s exists and is not a socket", path)
		}
		conn, dialErr := net.DialTimeout("unix", path, 500*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("listen unix: %s is in use", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("listen unix: remove stale socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("listen unix: %w", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen unix: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("listen unix: chmod: %w", err)
	}
	return listener, nil
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

// StartAdminAPI starts the admin API in this process, next to the SSH
// listener (ADSSH_ADMIN_LISTEN), so it sees the listener's sessions. It
// returns once the socket is bound; the same auth, keys, and audit rules as
// `admin serve` apply. A failed ADMIN_HTTP_START record refuses to start.
func (e *Engine) StartAdminAPI(listen, keysFile, apiKey string) error {
	var keys []AdminKey
	if keysFile != "" {
		loaded, err := LoadAdminKeysFile(keysFile)
		if err != nil {
			return fmt.Errorf("admin API: %w", err)
		}
		keys = loaded
	}
	listener, err := adminListen(context.Background(), listen)
	if err != nil {
		return fmt.Errorf("admin API: %w", err)
	}
	actual := listener.Addr().String()
	if listener.Addr().Network() == "unix" {
		actual = "unix:" + actual
	}
	if err := e.LogEvent(fmt.Sprintf("ADMIN_HTTP_START: listen=%s legacy=%t keys=%s",
		actual, apiKey != "", emptyDash(adminKeyFingerprints(keys)))); err != nil {
		_ = listener.Close()
		return fmt.Errorf("admin API: audit: %w", err)
	}
	slog.Info("admin api listening", "listen", actual, "named_keys", len(keys), "legacy_key", apiKey != "")
	server := adminHTTPServerTimeouts(NewAdminHTTPHandlerWithKeys(e, apiKey, keys))
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			slog.Error("admin api stopped", "error", err)
		}
	}()
	return nil
}
