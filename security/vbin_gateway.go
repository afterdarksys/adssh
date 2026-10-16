package security

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
	"mvdan.cc/sh/v3/interp"
)

type gatewayBinary struct{}

func (gatewayBinary) Name() string { return "gateway" }
func (gatewayBinary) Description() string {
	return "Policy-audited TCP gateway for SSH and internal service access"
}
func (gatewayBinary) Usage() string {
	return `gateway start --listen 127.0.0.1:0 [--listen-any] --target host:port [--name label]
gateway list
gateway stop <id>`
}

// Threats: `gateway start` resolves the target name once, before the policy
// decision, and every proxied connection dials that address. A DNS answer
// that changes after the check (rebinding) is not used, and policy can
// constrain input.gateway.target_ip as well as target_host. An unresolvable
// name fails closed. Not covered: a name whose address legitimately moves
// while the gateway is running keeps the old address until restarted.
//
// A gateway belongs to the session that started it. Only that session or a
// caller holding adssh-admin can stop it, and it is torn down when its
// session unregisters. It listens on loopback unless the caller holds
// adssh-admin and passes --listen-any, and on a port below 1024 only for
// adssh-admin. Over an SSH Run, start is refused and list shows the bound
// session's gateways only (sshListenerRuns).
type gatewaySession struct {
	ID     string
	Name   string
	Listen string
	Target string
	// dialAddr is the resolved address the policy decision saw. The proxy
	// dials it, never the name, so DNS cannot change the target after the
	// check.
	dialAddr string
	User     string
	// Owner is the session id that started the gateway.
	Owner    string
	Started  time.Time
	listener net.Listener
	cancel   context.CancelFunc
	engine   *Engine
}

// gatewayResolveTimeout bounds the one lookup of a gateway target name.
const gatewayResolveTimeout = 10 * time.Second

var gatewayLookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// resolveGatewayIP returns host as an address, resolving a name once.
func resolveGatewayIP(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), gatewayResolveTimeout)
	defer cancel()
	ips, err := gatewayLookupIP(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("gateway: target does not resolve")
	}
	return ips[0], nil
}

var (
	gatewayMu       sync.RWMutex
	gatewaySessions = map[string]*gatewaySession{}
	gatewaySeqMu    sync.Mutex
	gatewaySeq      int64
)

func (gatewayBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	if len(args) < 2 {
		return fmt.Errorf("gateway: usage: %s", gatewayBinary{}.Usage())
	}
	switch args[1] {
	case "start":
		return gatewayStart(ctx, hc, args[2:])
	case "list":
		owner := ""
		if sshRunFrom(ctx) {
			owner = SessionIDFromContext(ctx)
			if owner == "" {
				return fmt.Errorf("gateway: list requires a session")
			}
		}
		return gatewayList(hc, owner)
	case "stop":
		if len(args) != 3 {
			return fmt.Errorf("gateway: stop requires an id")
		}
		return gatewayStop(ctx, hc, args[2])
	default:
		return fmt.Errorf("gateway: unknown command %q", args[1])
	}
}

func gatewayStart(ctx context.Context, hc interp.HandlerContext, args []string) error {
	listenAddr := "127.0.0.1:0"
	target := ""
	name := ""
	listenAny := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--listen-any":
			listenAny = true
		case "--listen":
			if i+1 >= len(args) {
				return fmt.Errorf("gateway: --listen requires an address")
			}
			i++
			listenAddr = args[i]
		case "--target":
			if i+1 >= len(args) {
				return fmt.Errorf("gateway: --target requires host:port")
			}
			i++
			target = args[i]
		case "--name":
			if i+1 >= len(args) {
				return fmt.Errorf("gateway: --name requires a label")
			}
			i++
			name = args[i]
		default:
			return fmt.Errorf("gateway: unknown option %q", args[i])
		}
	}
	if target == "" {
		return fmt.Errorf("gateway: --target is required")
	}
	if err := validateGatewayAddress("listen", listenAddr); err != nil {
		return err
	}
	engine := engineFromContext(ctx)
	sessionID := SessionIDFromContext(ctx)
	if err := validateGatewayListen(listenAddr, listenAny, gatewayCallerIsAdmin(engine, sessionID)); err != nil {
		return err
	}
	if err := validateGatewayAddress("target", target); err != nil {
		return err
	}
	targetHost, targetPort, err := splitGatewayTarget(target)
	if err != nil {
		return err
	}
	// Resolve once; the decision sees the name and the address, and the
	// proxy dials only that address.
	targetIP, err := resolveGatewayIP(targetHost)
	if err != nil {
		return err
	}
	if err := engine.AuthorizeGateway(GatewayPolicyRequest{
		SessionID:  sessionID,
		Action:     "connect",
		Listen:     listenAddr,
		Name:       name,
		TargetHost: targetHost,
		TargetIP:   targetIP.String(),
		TargetPort: targetPort,
	}); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("gateway: listen: %w", err)
	}
	sessionCtx, cancel := context.WithCancel(context.Background())
	id := nextGatewayID()
	entry := &gatewaySession{
		ID:       id,
		Name:     name,
		Listen:   listener.Addr().String(),
		Target:   target,
		dialAddr: net.JoinHostPort(targetIP.String(), strconv.FormatUint(uint64(targetPort), 10)),
		User:     engine.buildPolicyContext("gateway", []string{"connect", target}, sessionID).User,
		Owner:    sessionID,
		Started:  time.Now().UTC(),
		listener: listener,
		cancel:   cancel,
		engine:   engine,
	}
	// Record before the gateway is registered or served. A failed write
	// closes the bound listener, which has not accepted a connection yet.
	if err := engine.LogEvent(fmt.Sprintf("GATEWAY_START: id=%s listen=%s target=%s user=%s name=%q",
		id, entry.Listen, target, entry.User, name)); err != nil {
		cancel()
		if closeErr := listener.Close(); closeErr != nil {
			return fmt.Errorf("gateway: audit: %w (close listener: %v)", err, closeErr)
		}
		return fmt.Errorf("gateway: audit: %w", err)
	}
	gatewayMu.Lock()
	gatewaySessions[id] = entry
	gatewayMu.Unlock()
	// The owner may have unregistered while the gateway was starting; its
	// hook has run, so tear this one down now.
	if sessionID != "" && sys.GetSession(sessionID) == nil && !isBound(engine, sessionID) {
		stopOwnedGateways(sessionID)
		return fmt.Errorf("gateway: session ended")
	}
	fmt.Fprintf(hc.Stdout, "gateway: id=%s listen=%s target=%s\n", id, entry.Listen, target)

	go serveGateway(sessionCtx, entry)
	return nil
}

// gatewayList prints the active gateways; a non-empty owner limits it to
// that session's.
func gatewayList(hc interp.HandlerContext, owner string) error {
	gatewayMu.RLock()
	sessions := make([]*gatewaySession, 0, len(gatewaySessions))
	for _, session := range gatewaySessions {
		if owner != "" && session.Owner != owner {
			continue
		}
		copy := *session
		sessions = append(sessions, &copy)
	}
	gatewayMu.RUnlock()
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].ID < sessions[j].ID })
	fmt.Fprintln(hc.Stdout, "Active Gateways:")
	for _, session := range sessions {
		fmt.Fprintf(hc.Stdout, "  - %s listen=%s target=%s user=%s age=%s",
			session.ID,
			session.Listen,
			session.Target,
			emptyDash(session.User),
			formatSessionDuration(time.Since(session.Started)),
		)
		if session.Name != "" {
			fmt.Fprintf(hc.Stdout, " name=%q", session.Name)
		}
		fmt.Fprintln(hc.Stdout)
	}
	return nil
}

// gatewayStop stops gateway id. A gateway owned by another session is
// refused unless the caller holds adssh-admin; the refusal does not say
// whether the id exists.
func gatewayStop(ctx context.Context, hc interp.HandlerContext, id string) error {
	engine := engineFromContext(ctx)
	caller := SessionIDFromContext(ctx)
	admin := gatewayCallerIsAdmin(engine, caller)
	gatewayMu.RLock()
	session := gatewaySessions[id]
	gatewayMu.RUnlock()
	if session == nil || (session.Owner != caller && !admin) {
		return fmt.Errorf("gateway: not found: %s", id)
	}
	// Record before the stop; a failed write leaves the gateway running.
	if err := engine.LogEvent(fmt.Sprintf("GATEWAY_STOP: id=%s listen=%s target=%s", id, session.Listen, session.Target)); err != nil {
		return fmt.Errorf("gateway: stop not recorded, gateway left running: %w", err)
	}
	gatewayMu.Lock()
	if gatewaySessions[id] == session {
		delete(gatewaySessions, id)
	}
	gatewayMu.Unlock()
	session.cancel()
	_ = session.listener.Close()
	fmt.Fprintf(hc.Stdout, "gateway: stopped %s\n", id)
	return nil
}

// gatewayCallerIsAdmin reports whether the session holds adssh-admin, as
// policy sees it (bound or registered groups, or an active elevation).
func gatewayCallerIsAdmin(engine *Engine, sessionID string) bool {
	pctx := engine.buildPolicyContext("gateway", nil, sessionID)
	if pctx.IdentityUnknown {
		return false
	}
	for _, group := range pctx.Groups {
		if group == RoleAdsshAdmin {
			return true
		}
	}
	return false
}

// stopOwnedGateways stops every gateway the session owns.
func stopOwnedGateways(owner string) {
	if owner == "" {
		return
	}
	gatewayMu.Lock()
	var stopped []*gatewaySession
	for id, session := range gatewaySessions {
		if session.Owner == owner {
			stopped = append(stopped, session)
			delete(gatewaySessions, id)
		}
	}
	gatewayMu.Unlock()
	for _, session := range stopped {
		session.cancel()
		_ = session.listener.Close()
		if session.engine != nil {
			// The owner is gone, so the gateway stops whether or not the
			// record is written; a failed write is reported, not dropped.
			if err := session.engine.LogEvent(fmt.Sprintf("GATEWAY_STOP: id=%s listen=%s target=%s reason=session_ended", session.ID, session.Listen, session.Target)); err != nil {
				warnUnrecordedRevocation("GATEWAY_STOP", err)
			}
		}
	}
}

func init() { sys.OnSessionUnregister(stopOwnedGateways) }

func serveGateway(ctx context.Context, session *gatewaySession) {
	go func() {
		<-ctx.Done()
		_ = session.listener.Close()
	}()
	for {
		conn, err := session.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "closed network connection") {
				return
			}
			continue
		}
		go proxyGatewayConnection(ctx, conn, session)
	}
}

func proxyGatewayConnection(ctx context.Context, client net.Conn, session *gatewaySession) {
	defer client.Close()
	record := newGatewayConnectionRecord(session)
	openedAt := time.Now().UTC()
	targetConn, err := net.DialTimeout("tcp", session.dialAddr, 10*time.Second)
	if err != nil {
		record.ClosedAt = time.Now().UTC().Format(time.RFC3339Nano)
		record.DurationMS = time.Since(openedAt).Milliseconds()
		record.CloseReason = "dial_failed"
		appendGatewayConnectionRecord(record)
		return
	}
	defer targetConn.Close()
	go func() {
		<-ctx.Done()
		_ = client.Close()
		_ = targetConn.Close()
	}()
	var bytesToTarget int64
	var bytesToClient int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(countingWriter{writer: targetConn, count: &bytesToTarget}, client)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(countingWriter{writer: client, count: &bytesToClient}, targetConn)
	}()
	wg.Wait()
	record.ClosedAt = time.Now().UTC().Format(time.RFC3339Nano)
	record.DurationMS = time.Since(openedAt).Milliseconds()
	record.BytesToTarget = bytesToTarget
	record.BytesToClient = bytesToClient
	record.CloseReason = "closed"
	if ctx.Err() != nil {
		record.CloseReason = "gateway_stopped"
	}
	appendGatewayConnectionRecord(record)
}

func nextGatewayID() string {
	gatewaySeqMu.Lock()
	defer gatewaySeqMu.Unlock()
	gatewaySeq++
	return "gw-" + strconv.FormatInt(gatewaySeq, 10)
}

func validateGatewayAddress(label, addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("gateway: invalid %s address %q", label, addr)
	}
	if host == "" {
		return fmt.Errorf("gateway: %s host is required", label)
	}
	if port == "" {
		return fmt.Errorf("gateway: %s port is required", label)
	}
	return nil
}

// validateGatewayListen refuses a non-loopback listen address unless
// listenAny is set and the caller is admin, and a port below 1024 unless
// the caller is admin. Port 0 picks an ephemeral port.
func validateGatewayListen(addr string, listenAny, admin bool) error {
	host, portString, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("gateway: invalid listen address %q", addr)
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return fmt.Errorf("gateway: invalid listen port %q", portString)
	}
	if port != 0 && port < 1024 && !admin {
		return fmt.Errorf("gateway: listen port %d needs adssh-admin", port)
	}
	ip := net.ParseIP(host)
	loopback := host == "localhost" || (ip != nil && ip.IsLoopback())
	if !loopback {
		if !listenAny {
			return fmt.Errorf("gateway: listen address %q is not loopback; pass --listen-any (adssh-admin only)", host)
		}
		if !admin {
			return fmt.Errorf("gateway: --listen-any needs adssh-admin")
		}
	}
	return nil
}

func splitGatewayTarget(target string) (string, uint32, error) {
	host, portString, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, fmt.Errorf("gateway: invalid target address %q", target)
	}
	port, err := strconv.ParseUint(portString, 10, 32)
	if err != nil || port == 0 || port > 65535 {
		return "", 0, fmt.Errorf("gateway: invalid target port %q", portString)
	}
	return host, uint32(port), nil
}

func init() { Register(gatewayBinary{}) }
