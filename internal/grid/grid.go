// Package grid is sah-grid membership: a loopback TLS listener that places,
// rehearses, and cancels supervised agent flights, go-git scratch worktree
// management, and the grid, flight, agent, worktree, and repo virtual
// binaries. It registers those binaries with security.Register from init, so
// a binary that blank-imports this package links them.
package grid

// Threats: a peer token, a remote flight, or a managed-agent checkout must
// not become root, skip policy, run git hooks, or read outside the scratch
// worktree. This code lives in internal/grid, outside the security package;
// its only enforcement is the policy Gate injected into the grid state
// (security.DefaultEngine() unless SetGate replaces it). A nil gate refuses
// every operation. Membership tokens are compared in constant time and never
// logged; the token file is opened with O_NOFOLLOW and refused unless fstat
// shows a regular file with no group or other bits. The flight CA file is
// read through internal/safefile, so a symlink, FIFO, or oversized file is
// refused. The listener is TLS 1.3 on a loopback address and is not the admin
// API. A parent allow does not bind the peer: each host evaluates policy
// locally and fails closed when no policy is loaded. A remote peer may cancel
// or read only flights it placed. Flights past their TTL are canceled and
// their agent sessions released.
// The scratch root lives under the XDG data dir, never os.TempDir(). It must
// be a real directory (not a symlink) owned by the euid with mode 0700, and no
// ancestor may be world-writable; destroy removes only worktree ids this grid
// recorded. An agent checkout clones only the source the operator bound to
// its flight at place time.
// Non-goals: this does not push policy, continue after a deny, or change the
// process uid. A frame lease_id does not authorize a command. It does not
// defend against another process running as the same uid, or against an
// embedder that injects a permissive gate.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"

	"github.com/afterdarksys/adssh/internal/config"
	"github.com/afterdarksys/adssh/internal/safefile"
	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/afterdarksys/adssh/security"
)

const (
	gridPeerUser     = "grid-peer"
	gridMaxFlights   = 64
	gridMaxBody      = 64 * 1024
	gridMaxCA        = 1 << 20
	gridMaxTokenFile = 4096
	gridMaxCat       = 1 << 20
	gridMaxArgs      = 32
	gridMaxArgLen    = 256

	// gridCancelledRetention is how long a canceled flight stays readable.
	gridCancelledRetention = time.Hour
	// flightStatusCanceled is a canceled flight's status. Grid members
	// exchange it, so it keeps the spelling already on the wire.
	flightStatusCanceled = "cancelled" //nolint:misspell // wire value shared with other grid members.
	// worktreeDestroying reserves a worktree id while destroy removes it, so
	// place cannot bind it in the meantime.
	worktreeDestroying = "\x00destroying"
)

// Gate is the policy engine the grid evaluates against. *security.Engine
// satisfies it.
type Gate interface {
	// PolicyLoaded reports whether a Rego policy is installed. The grid
	// refuses place, rehearse, cancel, and status without one.
	PolicyLoaded() bool
	// BuildPolicyContext resolves the principal for a command under sessionID.
	BuildPolicyContext(command string, args []string, sessionID string) security.PolicyContext
	// EvaluatePolicy evaluates a policy context.
	EvaluatePolicy(pctx security.PolicyContext) (bool, string, error)
}

// defaultEngineGate resolves security.DefaultEngine() on every call, because
// the binaries replace the default engine (security.SetDefaultEngine) after
// package init has run.
type defaultEngineGate struct{}

func (defaultEngineGate) PolicyLoaded() bool { return security.DefaultEngine().PolicyLoaded() }

func (defaultEngineGate) BuildPolicyContext(command string, args []string, sessionID string) security.PolicyContext {
	return security.DefaultEngine().BuildPolicyContext(command, args, sessionID)
}

func (defaultEngineGate) EvaluatePolicy(pctx security.PolicyContext) (bool, string, error) {
	return security.DefaultEngine().EvaluatePolicy(pctx)
}

var errNoGate = errors.New("grid: no policy gate")

// gridState is one process's grid membership. It is process-global (procGrid)
// because one adssh process is one grid member and the virtual binaries,
// which the registry constructs with no arguments, must share it. Every
// function that reads or changes it takes the state as its receiver.
type gridState struct {
	mu           sync.Mutex
	member       *gridMembership
	scratchRoot  string
	gate         Gate
	reapInterval time.Duration // how often a listening grid cancels expired flights
}

var (
	procGrid = &gridState{
		scratchRoot:  defaultScratchRoot(),
		gate:         defaultEngineGate{},
		reapInterval: 30 * time.Second,
	}

	commitHashPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	// gridIDPattern is the security package's role-name shape.
	gridIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,64}$`)
)

// SetGate replaces the policy gate of the process grid. A nil gate makes
// every grid operation refuse. It is for tests and embedders.
func SetGate(g Gate) {
	procGrid.setGate(g)
}

func (st *gridState) setGate(g Gate) {
	st.mu.Lock()
	st.gate = g
	st.mu.Unlock()
}

// gateFor returns the gate a virtual binary evaluates against: the engine
// that dispatched it, or the state gate when ctx carries none. It fails
// closed when the state gate is nil.
func (st *gridState) gateFor(ctx context.Context) (Gate, error) {
	st.mu.Lock()
	g := st.gate
	st.mu.Unlock()
	if g == nil {
		return nil, errNoGate
	}
	if eng := security.EngineFromContext(ctx); eng != nil {
		return eng, nil
	}
	return g, nil
}

// gateReady reports whether g is a non-nil gate with a policy loaded.
func gateReady(g Gate) bool {
	return g != nil && g.PolicyLoaded()
}

type gridError struct {
	Status  int
	message string
}

func (e *gridError) Error() string {
	if e == nil {
		return ""
	}
	return e.message
}

func gridErr(status int, format string, args ...any) error {
	return &gridError{Status: status, message: fmt.Sprintf(format, args...)}
}

type gridMembership struct {
	id        string
	tokenHash []byte
	drained   bool
	listenURL string
	server    *http.Server
	listener  net.Listener
	gate      Gate
	flights   map[string]*flightRecord
	agents    map[string]string
	worktrees map[string]string
	sessions  map[string]string
	serveErr  error
	stopReap  chan struct{}
}

type flightRecord struct {
	ID         string
	AgentID    string
	WorktreeID string
	SessionID  string
	User       string
	Status     string
	Reason     string
	ExpiresAt  time.Time
	Remote     bool
	// Source is the only repository an agent of this flight may check out.
	Source      string
	CancelledAt time.Time
}

type flightWire struct {
	Action     string   `json:"action,omitempty"`
	FlightID   string   `json:"flight_id,omitempty"`
	AgentID    string   `json:"agent_id,omitempty"`
	WorktreeID string   `json:"worktree_id,omitempty"`
	TTLSeconds int64    `json:"ttl_seconds,omitempty"`
	Rehearsal  bool     `json:"rehearsal,omitempty"`
	Command    []string `json:"command,omitempty"`
	// User is accepted so a caller can send it, and ignored. The peer
	// session user is always grid-peer.
	User string `json:"user,omitempty"`
}

type flightResult struct {
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	FlightID  string `json:"flight_id,omitempty"`
}

type placeOpts struct {
	FlightID   string
	AgentID    string
	WorktreeID string
	TTL        time.Duration
	User       string
	Remote     bool
	Gate       Gate
	Source     string
}

type flightClientOpts struct {
	Host       string
	CAFile     string
	ServerName string
	TokenFile  string
	Action     string
	Wire       flightWire
}

func writeMembershipToken(path string, raw []byte) (fingerprint string, err error) {
	encoded := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(encoded, raw)
	fingerprint = fingerprintToken(string(encoded))
	payload := make([]byte, len(encoded)+1)
	copy(payload, encoded)
	payload[len(encoded)] = '\n'
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
		for i := range encoded {
			encoded[i] = 0
		}
		for i := range payload {
			payload[i] = 0
		}
	}()

	file, openErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if openErr != nil {
		return "", openErr
	}
	var writeErr error
	if _, err := file.Write(payload); err != nil {
		writeErr = err
	}
	if err := file.Close(); err != nil {
		writeErr = errors.Join(writeErr, err)
	}
	if writeErr != nil {
		if rmErr := os.Remove(path); rmErr != nil {
			writeErr = errors.Join(writeErr, rmErr)
		}
		return "", writeErr
	}
	if err := os.Chmod(path, 0o600); err != nil {
		if rmErr := os.Remove(path); rmErr != nil {
			return "", errors.Join(err, rmErr)
		}
		return "", err
	}
	return fingerprint, nil
}

// fingerprintToken is the hex SHA-256 of a token, the only form printed.
func fingerprintToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func loadMembershipToken(path string) (string, []byte, error) {
	// O_NOFOLLOW refuses a symlink at open time, and every check below reads
	// the opened descriptor, so the file cannot be swapped after the check.
	// O_NONBLOCK keeps a planted FIFO from blocking the open.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK) {
			return "", nil, fmt.Errorf("grid: token file is a symlink")
		}
		return "", nil, fmt.Errorf("grid: token file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", nil, fmt.Errorf("grid: token file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("grid: token file is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", nil, fmt.Errorf("grid: token file is readable or writable by group or others")
	}
	if info.Size() > gridMaxTokenFile {
		return "", nil, fmt.Errorf("grid: token file is too large")
	}
	data, err := io.ReadAll(io.LimitReader(file, gridMaxTokenFile+1))
	if err != nil {
		return "", nil, fmt.Errorf("grid: token file: %w", err)
	}
	if len(data) > gridMaxTokenFile {
		for i := range data {
			data[i] = 0
		}
		return "", nil, fmt.Errorf("grid: token file is too large")
	}
	trimmed := strings.TrimSpace(string(data))
	for i := range data {
		data[i] = 0
	}
	sum := sha256.Sum256([]byte(trimmed))
	return trimmed, append([]byte(nil), sum[:]...), nil
}

func gridTokenMatches(stored []byte, bearer string) bool {
	var got [sha256.Size]byte
	if len(bearer) <= gridMaxTokenFile {
		got = sha256.Sum256([]byte(strings.TrimSpace(bearer)))
	}
	expect := stored
	if len(expect) != sha256.Size {
		expect = make([]byte, sha256.Size)
	}
	equal := subtle.ConstantTimeCompare(expect, got[:]) == 1
	if bearer == "" || len(bearer) > gridMaxTokenFile || len(stored) != sha256.Size {
		return false
	}
	return equal
}

func validGridID(id string) bool {
	return gridIDPattern.MatchString(id)
}

// defaultScratchRoot keeps worktrees under the adssh XDG data dir. There is no
// XDG state helper in internal/config, so the data dir is the closest one.
func defaultScratchRoot() string {
	return filepath.Join(config.XDGDataHome(), "worktrees")
}

func (st *gridState) setScratchRoot(dir string) {
	st.mu.Lock()
	st.scratchRoot = dir
	st.mu.Unlock()
}

func (st *gridState) currentScratchRoot() string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.scratchRoot
}

func (st *gridState) initGrid(id, tokenFile, tokenOut string) (string, string, error) {
	if tokenFile != "" && tokenOut != "" {
		return "", "", fmt.Errorf("grid: --token-file and --token-out cannot be combined")
	}
	if tokenFile == "" && tokenOut == "" {
		return "", "", fmt.Errorf("grid: --token-file or --token-out is required")
	}
	if id != "" && !validGridID(id) {
		return "", "", fmt.Errorf("grid: invalid id")
	}

	st.mu.Lock()
	already := st.member != nil
	st.mu.Unlock()
	if already {
		return "", "", fmt.Errorf("grid: already initialized")
	}

	if id == "" {
		var buf [8]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return "", "", fmt.Errorf("grid: random id: %w", err)
		}
		id = "g" + hex.EncodeToString(buf[:])
	}

	var hash []byte
	var fingerprint string
	if tokenFile != "" {
		_, loaded, err := loadMembershipToken(tokenFile)
		if err != nil {
			return "", "", err
		}
		hash = loaded
		fingerprint = hex.EncodeToString(hash)
	} else {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return "", "", fmt.Errorf("grid: random token: %w", err)
		}
		fp, err := writeMembershipToken(tokenOut, raw)
		if err != nil {
			return "", "", err
		}
		decoded, err := hex.DecodeString(fp)
		if err != nil || len(decoded) != sha256.Size {
			return "", "", fmt.Errorf("grid: token fingerprint")
		}
		hash = decoded
		fingerprint = fp
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	if st.member != nil {
		return "", "", fmt.Errorf("grid: already initialized")
	}
	st.member = &gridMembership{
		id:        id,
		tokenHash: hash,
		flights:   map[string]*flightRecord{},
		agents:    map[string]string{},
		worktrees: map[string]string{},
		sessions:  map[string]string{},
	}
	return id, fingerprint, nil
}

func (st *gridState) gridStatus() (id, fingerprint, listen string, drained bool, flights int, err error) {
	st.reapExpiredFlights(time.Now())
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.member == nil {
		return "", "", "", false, 0, fmt.Errorf("grid: not initialized")
	}
	live := 0
	for _, flight := range st.member.flights {
		if flight.Status != flightStatusCanceled {
			live++
		}
	}
	fp := ""
	if len(st.member.tokenHash) == sha256.Size {
		fp = hex.EncodeToString(st.member.tokenHash)
	}
	return st.member.id, fp, st.member.listenURL, st.member.drained, live, nil
}

func (st *gridState) drainGrid() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.member == nil {
		return fmt.Errorf("grid: not initialized")
	}
	st.member.drained = true
	return nil
}

func (st *gridState) listenGrid(listen, certFile, keyFile, tokenFile string, gate Gate) (string, error) {
	cert, hexToken, hash, err := loadGridListenConfig(listen, certFile, keyFile, tokenFile)
	if err != nil {
		return "", err
	}
	ln, err := tls.Listen("tcp", listen, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		return "", err
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(st.gridFlightHandler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	stop := make(chan struct{})
	listenURL, err := st.installGridServer(srv, ln, gate, hexToken, hash, stop)
	if err != nil {
		if closeErr := ln.Close(); closeErr != nil {
			return "", errors.Join(err, closeErr)
		}
		return "", err
	}

	go st.runGridReaper(stop, st.reapInterval)
	go func() {
		// tls.Listen already owns the handshake. ServeTLS would listen again.
		serveErr := srv.Serve(ln)
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			st.mu.Lock()
			if st.member != nil && st.member.server == srv {
				st.member.serveErr = serveErr
			}
			st.mu.Unlock()
		}
	}()
	return listenURL, nil
}

func loadGridListenConfig(listen, certFile, keyFile, tokenFile string) (tls.Certificate, string, []byte, error) {
	if strings.TrimSpace(certFile) == "" || strings.TrimSpace(keyFile) == "" || strings.TrimSpace(tokenFile) == "" {
		return tls.Certificate{}, "", nil, fmt.Errorf("grid: cert, key, and token file are required")
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return tls.Certificate{}, "", nil, fmt.Errorf("grid: listen address must be a loopback IP")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return tls.Certificate{}, "", nil, fmt.Errorf("grid: listen address must be a loopback IP")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, "", nil, fmt.Errorf("grid: certificate: %w", err)
	}
	hexToken, hash, err := loadMembershipToken(tokenFile)
	if err != nil {
		return tls.Certificate{}, "", nil, err
	}
	return cert, hexToken, hash, nil
}

// installGridServer records the listener on the grid, or refuses when the
// grid is missing, already listening, or the token does not match.
func (st *gridState) installGridServer(srv *http.Server, ln net.Listener, gate Gate, hexToken string, hash []byte, stop chan struct{}) (string, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.member == nil {
		return "", fmt.Errorf("grid: not initialized")
	}
	if st.member.listener != nil {
		return "", fmt.Errorf("grid: already listening")
	}
	if len(st.member.tokenHash) == sha256.Size {
		if !gridTokenMatches(st.member.tokenHash, hexToken) {
			return "", fmt.Errorf("grid: token mismatch")
		}
	} else {
		st.member.tokenHash = append([]byte(nil), hash...)
	}
	st.member.server = srv
	st.member.listener = ln
	st.member.listenURL = "https://" + ln.Addr().String()
	st.member.gate = gate
	st.member.stopReap = stop
	return st.member.listenURL, nil
}

// runGridReaper cancels expired flights on every tick until stop closes.
func (st *gridState) runGridReaper(stop <-chan struct{}, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			st.reapExpiredFlights(now)
		}
	}
}

// reapExpiredFlights cancels every live flight past its TTL, releases its
// agent session, and forgets canceled flights older than the retention.
func (st *gridState) reapExpiredFlights(now time.Time) {
	st.mu.Lock()
	if st.member == nil {
		st.mu.Unlock()
		return
	}
	var released []string
	for id, rec := range st.member.flights {
		if rec.Status == flightStatusCanceled {
			if now.Sub(rec.CancelledAt) > gridCancelledRetention {
				delete(st.member.flights, id)
			}
			continue
		}
		if !now.Before(rec.ExpiresAt) {
			released = append(released, st.cancelFlightLocked(rec, "lease expired", now))
		}
	}
	st.mu.Unlock()
	releaseAgentSessions(released)
}

// cancelFlightLocked marks rec canceled and frees its agent and worktree
// ids. The caller holds gridMu and must release the returned session.
func (st *gridState) cancelFlightLocked(rec *flightRecord, reason string, now time.Time) string {
	rec.Status = flightStatusCanceled
	rec.Reason = reason
	rec.CancelledAt = now
	if st.member.agents[rec.AgentID] == rec.ID {
		delete(st.member.agents, rec.AgentID)
	}
	if st.member.worktrees[rec.WorktreeID] == rec.ID {
		// The directory stays, so the id stays recorded and destroyable.
		st.member.worktrees[rec.WorktreeID] = ""
	}
	delete(st.member.sessions, rec.SessionID)
	return rec.SessionID
}

func releaseAgentSessions(ids []string) {
	for _, id := range ids {
		if session := sys.GetSession(id); session != nil {
			session.ClearManagedAgent()
		}
		sys.UnregisterSession(id)
	}
}

// resetGridState stops the listener, releases agent sessions, and restores
// the default scratch root and gate. Tests use it between cases.
func (st *gridState) resetGridState() {
	st.mu.Lock()
	var srv *http.Server
	var ln net.Listener
	if st.member != nil {
		srv = st.member.server
		ln = st.member.listener
		if st.member.stopReap != nil {
			close(st.member.stopReap)
			st.member.stopReap = nil
		}
	}
	st.mu.Unlock()

	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
	}
	if ln != nil {
		_ = ln.Close()
	}

	st.mu.Lock()
	var sessionIDs []string
	if st.member != nil {
		for id := range st.member.sessions {
			sessionIDs = append(sessionIDs, id)
		}
	}
	st.member = nil
	st.scratchRoot = defaultScratchRoot()
	st.gate = defaultEngineGate{}
	st.mu.Unlock()

	releaseAgentSessions(sessionIDs)
}

func (st *gridState) gridFlightHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/flight" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.ContentLength > gridMaxBody {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}

	auth := r.Header.Get("Authorization")
	bearer := ""
	const bearerPrefix = "Bearer "
	if strings.HasPrefix(auth, bearerPrefix) {
		bearer = strings.TrimPrefix(auth, bearerPrefix)
	}
	st.mu.Lock()
	var stored []byte
	var gate Gate
	if st.member != nil {
		stored = append([]byte(nil), st.member.tokenHash...)
		gate = st.member.gate
	}
	if st.gate == nil {
		// SetGate(nil) also refuses a listener installed before it.
		gate = nil
	}
	st.mu.Unlock()
	if !gridTokenMatches(stored, bearer) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	body := http.MaxBytesReader(w, r.Body, gridMaxBody)
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		var maxBytes *http.MaxBytesError
		if errors.As(err, &maxBytes) || r.ContentLength > gridMaxBody {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var wire flightWire
	if err := json.Unmarshal(data, &wire); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	action := wire.Action
	if action == "" {
		if wire.Rehearsal {
			action = "rehearse"
		} else {
			action = "place"
		}
	}
	result, callErr := st.dispatchFlightAction(gate, action, wire, true)
	if callErr != nil {
		writeGridHTTPError(w, callErr)
		return
	}
	writeFlightResult(w, result)
}

func (st *gridState) dispatchFlightAction(gate Gate, action string, wire flightWire, remote bool) (flightResult, error) {
	switch action {
	case "place":
		if !gateReady(gate) {
			return flightResult{}, gridErr(http.StatusForbidden, "policy_required")
		}
		if wire.TTLSeconds < 1 || wire.TTLSeconds > 86400 {
			return flightResult{}, gridErr(http.StatusBadRequest, "flight: ttl is invalid")
		}
		return st.placeFlight(placeOpts{
			FlightID:   wire.FlightID,
			AgentID:    wire.AgentID,
			WorktreeID: wire.WorktreeID,
			TTL:        time.Duration(wire.TTLSeconds) * time.Second,
			User:       gridPeerUser,
			Remote:     true,
			Gate:       gate,
		})
	case "rehearse", "rehearsal":
		if !gateReady(gate) {
			return flightResult{}, gridErr(http.StatusForbidden, "policy_required")
		}
		return st.rehearseFlight(gate, wire.FlightID, wire.Command, remote)
	case "cancel", "status":
		if !gateReady(gate) {
			return flightResult{}, gridErr(http.StatusForbidden, "policy_required")
		}
		if action == "cancel" {
			return st.cancelFlight(wire.FlightID, remote)
		}
		return st.flightStatus(wire.FlightID, remote)
	default:
		return flightResult{}, gridErr(http.StatusBadRequest, "unknown action")
	}
}

func writeGridHTTPError(w http.ResponseWriter, err error) {
	var ge *gridError
	if errors.As(err, &ge) && ge.Status != 0 {
		http.Error(w, ge.Error(), ge.Status)
		return
	}
	http.Error(w, "grid: request failed", http.StatusInternalServerError)
}

func writeFlightResult(w http.ResponseWriter, result flightResult) {
	buf, err := json.Marshal(result)
	if err != nil {
		http.Error(w, "grid: request failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf)
}

func (st *gridState) placeFlight(opts placeOpts) (flightResult, error) {
	user, source, err := validatePlaceOpts(opts)
	if err != nil {
		return flightResult{}, err
	}
	st.mu.Lock()
	if st.member == nil {
		st.mu.Unlock()
		return flightResult{}, fmt.Errorf("grid: not initialized")
	}
	drained := st.member.drained
	st.mu.Unlock()
	if drained {
		return flightResult{}, gridErr(http.StatusConflict, "drained")
	}
	now := time.Now().UTC()
	st.reapExpiredFlights(now)

	dir, err := st.confinedWorktreePath(opts.WorktreeID)
	if err != nil {
		return flightResult{}, err
	}
	if err := ensureWorktreeDir(dir); err != nil {
		return flightResult{}, fmt.Errorf("flight: worktree directory: %w", err)
	}

	rec := &flightRecord{
		ID:         opts.FlightID,
		AgentID:    opts.AgentID,
		WorktreeID: opts.WorktreeID,
		SessionID:  "agent-" + opts.AgentID,
		User:       user,
		Status:     "placed",
		ExpiresAt:  now.Add(opts.TTL),
		Remote:     opts.Remote,
		Source:     source,
	}
	session := &sys.Session{ID: rec.SessionID, User: user}
	session.BindManagedAgent(&sys.ManagedAgent{
		ID:        opts.AgentID,
		FlightID:  opts.FlightID,
		Worktree:  opts.WorktreeID,
		Allow:     security.AgentAllowlist(),
		ExpiresAt: rec.ExpiresAt,
	})
	if err := st.registerFlight(rec, session, now); err != nil {
		return flightResult{}, err
	}
	return flightResult{Status: "placed", SessionID: rec.SessionID, FlightID: opts.FlightID}, nil
}

// validatePlaceOpts returns the session user and the cleaned bound source.
func validatePlaceOpts(opts placeOpts) (string, string, error) {
	if !validGridID(opts.FlightID) || !validGridID(opts.AgentID) || !validGridID(opts.WorktreeID) {
		return "", "", gridErr(http.StatusBadRequest, "flight: invalid id")
	}
	if opts.TTL < time.Second || opts.TTL > 24*time.Hour {
		return "", "", gridErr(http.StatusBadRequest, "flight: ttl is invalid")
	}
	user := opts.User
	if opts.Remote {
		user = gridPeerUser
	}
	if user == "" {
		return "", "", gridErr(http.StatusBadRequest, "flight: user is required")
	}
	if !gateReady(opts.Gate) {
		return "", "", gridErr(http.StatusForbidden, "policy_required")
	}
	source := ""
	if opts.Source != "" {
		// A peer would name a path on this host, so only the local operator
		// binds a source.
		if opts.Remote {
			return "", "", gridErr(http.StatusBadRequest, "flight: a remote flight cannot bind a source")
		}
		src, err := validateCheckoutSource(opts.Source)
		if err != nil {
			return "", "", err
		}
		source = filepath.Clean(src)
	}
	return user, source, nil
}

// registerFlight records rec and registers its agent session, refusing
// duplicate ids, a drained grid, and a full flight table.
func (st *gridState) registerFlight(rec *flightRecord, session *sys.Session, now time.Time) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.member == nil {
		return fmt.Errorf("grid: not initialized")
	}
	if st.member.drained {
		return gridErr(http.StatusConflict, "drained")
	}
	_, flightTaken := st.member.flights[rec.ID]
	_, agentTaken := st.member.agents[rec.AgentID]
	_, sessionTaken := st.member.sessions[rec.SessionID]
	if flightTaken || agentTaken || sessionTaken || st.member.worktrees[rec.WorktreeID] != "" ||
		sys.GetSession(rec.SessionID) != nil {
		return gridErr(http.StatusConflict, "flight: duplicate id")
	}
	live := 0
	for _, flight := range st.member.flights {
		if flight.Status != flightStatusCanceled && now.Before(flight.ExpiresAt) {
			live++
		}
	}
	if live >= gridMaxFlights {
		return gridErr(http.StatusConflict, "flight: too many flights")
	}
	if err := sys.RegisterSession(session); err != nil {
		return err
	}
	st.member.flights[rec.ID] = rec
	st.member.agents[rec.AgentID] = rec.ID
	st.member.worktrees[rec.WorktreeID] = rec.ID
	st.member.sessions[rec.SessionID] = rec.ID
	return nil
}

func (st *gridState) rehearseFlight(gate Gate, flightID string, command []string, remote bool) (flightResult, error) {
	if !validGridID(flightID) {
		return flightResult{}, gridErr(http.StatusBadRequest, "flight: invalid id")
	}
	if err := validateFlightCommand(command); err != nil {
		return flightResult{}, err
	}
	if !gateReady(gate) {
		return flightResult{}, gridErr(http.StatusForbidden, "policy_required")
	}
	st.mu.Lock()
	if st.member == nil {
		st.mu.Unlock()
		return flightResult{}, fmt.Errorf("grid: not initialized")
	}
	rec := st.member.flights[flightID]
	if rec == nil {
		st.mu.Unlock()
		return flightResult{}, gridErr(http.StatusNotFound, "flight: not found")
	}
	sessionID := rec.SessionID
	status := rec.Status
	st.mu.Unlock()

	if !security.AgentCommandAllowed(command[0]) {
		reason := fmt.Sprintf("agent cannot run %q", command[0])
		st.rememberFlightDenial(flightID, reason, status)
		return flightResult{Status: "denied", Reason: reason, FlightID: flightID}, nil
	}
	if status == flightStatusCanceled {
		return flightResult{}, gridErr(http.StatusForbidden, "flight: agent lease expired")
	}
	session := sys.GetSession(sessionID)
	if session == nil {
		return flightResult{}, gridErr(http.StatusForbidden, "flight: agent lease expired")
	}
	agent := session.ManagedAgent()
	if agent == nil || !time.Now().Before(agent.ExpiresAt) {
		return flightResult{}, gridErr(http.StatusForbidden, "flight: agent lease expired")
	}

	pctx := gate.BuildPolicyContext(command[0], command[1:], sessionID)
	if remote {
		pctx.User = gridPeerUser
		pctx.Groups = nil
		pctx.Elevation = nil
	}
	allowed, reason, err := gate.EvaluatePolicy(pctx)
	if err != nil {
		return flightResult{}, gridErr(http.StatusForbidden, "flight: policy evaluation failed")
	}
	if !allowed {
		if reason == "" {
			reason = "denied"
		}
		st.rememberFlightDenial(flightID, reason, status)
		return flightResult{Status: "denied", Reason: reason, FlightID: flightID}, nil
	}
	st.mu.Lock()
	if st.member != nil {
		if rec := st.member.flights[flightID]; rec != nil && rec.Status != flightStatusCanceled {
			rec.Status = "rehearsed"
			rec.Reason = ""
		}
	}
	st.mu.Unlock()
	return flightResult{Status: "rehearsed", FlightID: flightID}, nil
}

func (st *gridState) rememberFlightDenial(flightID, reason, previousStatus string) {
	if previousStatus == flightStatusCanceled {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.member == nil {
		return
	}
	rec := st.member.flights[flightID]
	if rec == nil || rec.Status == flightStatusCanceled {
		return
	}
	rec.Status = "denied"
	rec.Reason = reason
}

// cancelFlight cancels a flight. remoteOnly is set for a grid peer, which
// may cancel only flights a peer placed; a local flight reads as not found.
func (st *gridState) cancelFlight(id string, remoteOnly bool) (flightResult, error) {
	if !validGridID(id) {
		return flightResult{}, gridErr(http.StatusBadRequest, "flight: invalid id")
	}
	st.mu.Lock()
	if st.member == nil {
		st.mu.Unlock()
		return flightResult{}, fmt.Errorf("grid: not initialized")
	}
	rec := st.member.flights[id]
	if rec == nil || (remoteOnly && !rec.Remote) {
		st.mu.Unlock()
		return flightResult{}, gridErr(http.StatusNotFound, "flight: not found")
	}
	sessionID := st.cancelFlightLocked(rec, "", time.Now())
	st.mu.Unlock()

	releaseAgentSessions([]string{sessionID})
	return flightResult{Status: flightStatusCanceled, FlightID: id}, nil
}

// flightStatus reads a flight. remoteOnly hides local flights from a peer.
func (st *gridState) flightStatus(id string, remoteOnly bool) (flightResult, error) {
	if !validGridID(id) {
		return flightResult{}, gridErr(http.StatusBadRequest, "flight: invalid id")
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.member == nil {
		return flightResult{}, fmt.Errorf("grid: not initialized")
	}
	rec := st.member.flights[id]
	if rec == nil || (remoteOnly && !rec.Remote) {
		return flightResult{}, gridErr(http.StatusNotFound, "flight: not found")
	}
	return flightResult{
		Status:    rec.Status,
		Reason:    rec.Reason,
		SessionID: rec.SessionID,
		FlightID:  rec.ID,
	}, nil
}

func validateFlightCommand(command []string) error {
	if len(command) == 0 || len(command) > gridMaxArgs {
		return gridErr(http.StatusBadRequest, "flight: command is invalid")
	}
	for _, arg := range command {
		if arg == "" || len(arg) > gridMaxArgLen {
			return gridErr(http.StatusBadRequest, "flight: command is invalid")
		}
	}
	return nil
}

func (st *gridState) listAgents() []flightRecord {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.member == nil {
		return nil
	}
	out := make([]flightRecord, 0, len(st.member.agents))
	for agentID, flightID := range st.member.agents {
		rec := st.member.flights[flightID]
		if rec == nil {
			out = append(out, flightRecord{AgentID: agentID, ID: flightID})
			continue
		}
		out = append(out, *rec)
	}
	return out
}

func postFlight(gate Gate, opts flightClientOpts) (flightResult, error) {
	target, err := flightEndpoint(opts)
	if err != nil {
		return flightResult{}, err
	}
	action := opts.Action
	if action == "" {
		action = opts.Wire.Action
	}
	if action == "place" || action == "rehearse" || action == "rehearsal" {
		if !gateReady(gate) {
			return flightResult{}, gridErr(http.StatusForbidden, "policy_required")
		}
	}
	pool, err := loadFlightCA(opts.CAFile)
	if err != nil {
		return flightResult{}, err
	}
	hexToken, _, err := loadMembershipToken(opts.TokenFile)
	if err != nil {
		return flightResult{}, err
	}
	if opts.Wire.Action == "" {
		opts.Wire.Action = action
	}
	payload, err := json.Marshal(opts.Wire)
	if err != nil {
		return flightResult{}, fmt.Errorf("flight: request failed")
	}
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return flightResult{}, fmt.Errorf("flight: request failed")
	}
	req.Header.Set("Authorization", "Bearer "+hexToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := newFlightClient(pool, opts.ServerName).Do(req)
	if err != nil {
		return flightResult{}, err
	}
	defer resp.Body.Close()
	return decodeFlightResponse(resp)
}

// flightEndpoint validates the peer URL and the remote flags, and returns
// the flight endpoint with any query or fragment removed.
func flightEndpoint(opts flightClientOpts) (string, error) {
	if opts.CAFile == "" {
		return "", fmt.Errorf("flight: --host requires --ca")
	}
	parsed, err := url.Parse(opts.Host)
	if err != nil {
		return "", fmt.Errorf("flight: host must be https")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("flight: credentials are rejected")
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("flight: host must be https")
	}
	if opts.TokenFile == "" {
		return "", fmt.Errorf("flight: --host requires --token-file")
	}
	parsed.Path = "/v1/flight"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func newFlightClient(pool *x509.CertPool, serverName string) *http.Client {
	if serverName == "" {
		serverName = "localhost"
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("flight: redirects are refused")
		},
		Transport: &http.Transport{
			Proxy: nil,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    pool,
				ServerName: serverName,
			},
		},
	}
}

func decodeFlightResponse(resp *http.Response) (flightResult, error) {
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, gridMaxCA+1))
	if err != nil {
		return flightResult{}, fmt.Errorf("flight: response failed")
	}
	if int64(len(respBody)) > gridMaxCA {
		return flightResult{}, fmt.Errorf("flight: response too large")
	}
	text := strings.TrimSpace(string(respBody))
	if resp.StatusCode != http.StatusOK {
		return flightResult{}, fmt.Errorf("flight: %s", text)
	}
	var result flightResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return flightResult{}, fmt.Errorf("flight: %s", text)
	}
	if result.Status == "denied" {
		return result, fmt.Errorf("flight: denied: %s", result.Reason)
	}
	return result, nil
}

// loadFlightCA reads the CA bundle through safefile: no symlink, no FIFO, and
// no more than gridMaxCA bytes, all checked on the opened descriptor.
func loadFlightCA(path string) (*x509.CertPool, error) {
	file, info, err := safefile.Open(nil, path)
	if err != nil {
		return nil, fmt.Errorf("flight: ca file: %w", err)
	}
	defer file.Close()
	data, err := safefile.ReadAll(file, info, gridMaxCA)
	if errors.Is(err, safefile.ErrTooLarge) {
		return nil, fmt.Errorf("flight: ca file is too large")
	}
	if err != nil {
		return nil, fmt.Errorf("flight: ca file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("flight: ca file has no certificates")
	}
	return pool, nil
}

func (st *gridState) createWorktree(id string) (string, error) {
	if !validGridID(id) {
		return "", fmt.Errorf("worktree: invalid id")
	}
	path, err := st.confinedWorktreePath(id)
	if err != nil {
		return "", err
	}
	st.mu.Lock()
	if st.member == nil {
		st.mu.Unlock()
		return "", fmt.Errorf("grid: not initialized")
	}
	if _, ok := st.member.worktrees[id]; ok {
		st.mu.Unlock()
		return "", fmt.Errorf("worktree: duplicate id")
	}
	st.mu.Unlock()
	if err := ensureWorktreeDir(path); err != nil {
		return "", fmt.Errorf("worktree: directory: %w", err)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.member == nil {
		return "", fmt.Errorf("grid: not initialized")
	}
	if _, ok := st.member.worktrees[id]; ok {
		return "", fmt.Errorf("worktree: duplicate id")
	}
	st.member.worktrees[id] = ""
	return path, nil
}

// destroyWorktree removes a worktree this grid recorded and that no live
// flight holds. An unrecorded id is refused even if the directory exists.
func (st *gridState) destroyWorktree(id string) error {
	if !validGridID(id) {
		return fmt.Errorf("worktree: invalid id")
	}
	st.mu.Lock()
	if st.member == nil {
		st.mu.Unlock()
		return fmt.Errorf("grid: not initialized")
	}
	flightID, ok := st.member.worktrees[id]
	if !ok {
		st.mu.Unlock()
		return fmt.Errorf("worktree: not found")
	}
	if flightID != "" {
		st.mu.Unlock()
		return fmt.Errorf("worktree: in use")
	}
	st.member.worktrees[id] = worktreeDestroying
	st.mu.Unlock()

	err := st.removeWorktreeDir(id)
	st.mu.Lock()
	if st.member != nil && st.member.worktrees[id] == worktreeDestroying {
		if err == nil {
			delete(st.member.worktrees, id)
		} else {
			st.member.worktrees[id] = ""
		}
	}
	st.mu.Unlock()
	return err
}

func (st *gridState) removeWorktreeDir(id string) error {
	path, err := st.confinedWorktreePath(id)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("worktree: not found")
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("worktree: destination is a symlink")
	}
	if !info.IsDir() {
		return fmt.Errorf("worktree: destination is not a directory")
	}
	return os.RemoveAll(path)
}

// agentCheckoutSource returns the source bound to agent's flight. A from
// value the agent supplies must name that same source.
func (st *gridState) agentCheckoutSource(agent *sys.ManagedAgent, from string) (string, error) {
	st.mu.Lock()
	var rec *flightRecord
	if st.member != nil {
		rec = st.member.flights[agent.FlightID]
	}
	bound := ""
	if rec != nil && rec.AgentID == agent.ID && rec.Status != flightStatusCanceled {
		bound = rec.Source
	}
	st.mu.Unlock()
	if bound == "" {
		return "", fmt.Errorf("worktree: agent has no bound source")
	}
	if from == "" {
		return bound, nil
	}
	src, err := validateCheckoutSource(from)
	if err != nil {
		return "", err
	}
	if filepath.Clean(src) != bound {
		return "", fmt.Errorf("worktree: source is not the flight's bound source")
	}
	return bound, nil
}

func validateCheckoutSource(src string) (string, error) {
	if strings.Contains(src, "://") {
		parsed, err := url.Parse(src)
		if err != nil || parsed.User != nil {
			if err == nil && parsed.User != nil {
				return "", fmt.Errorf("worktree: credentials are rejected")
			}
			return "", fmt.Errorf("worktree: source must be an absolute path")
		}
		if parsed.User != nil {
			return "", fmt.Errorf("worktree: credentials are rejected")
		}
		if parsed.Scheme != "" && parsed.Scheme != "file" {
			return "", fmt.Errorf("worktree: remote URLs are rejected")
		}
		if parsed.Scheme == "file" {
			host := parsed.Hostname()
			if host != "" && !strings.EqualFold(host, "localhost") {
				return "", fmt.Errorf("worktree: source must be an absolute path")
			}
			if !filepath.IsAbs(parsed.Path) {
				return "", fmt.Errorf("worktree: source must be an absolute path")
			}
			return parsed.Path, nil
		}
	}
	if strings.Contains(src, ":") && !strings.Contains(src, "://") {
		return "", fmt.Errorf("worktree: remote URLs are rejected")
	}
	if !filepath.IsAbs(src) {
		return "", fmt.Errorf("worktree: source must be an absolute path")
	}
	return src, nil
}

func (st *gridState) checkoutWorktree(id, source, rev string) error {
	src, err := validateCheckoutSource(source)
	if err != nil {
		return err
	}
	if !commitHashPattern.MatchString(rev) {
		return fmt.Errorf("worktree: rev must be a 40-character commit hash")
	}
	dest, err := st.confinedWorktreePath(id)
	if err != nil {
		return err
	}
	if err := ensureWorktreeDir(dest); err != nil {
		return fmt.Errorf("worktree: checkout failed: %w", err)
	}
	repo, err := git.PlainClone(dest, false, &git.CloneOptions{
		URL:        src,
		NoCheckout: true,
	})
	if err != nil {
		return fmt.Errorf("worktree: checkout failed: %w", err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("worktree: checkout failed: %w", err)
	}
	if err := worktree.Checkout(&git.CheckoutOptions{
		Hash:  plumbing.NewHash(rev),
		Force: true,
	}); err != nil {
		return fmt.Errorf("worktree: checkout failed: %w", err)
	}
	head, err := repo.Head()
	if err != nil {
		return fmt.Errorf("worktree: checkout failed: %w", err)
	}
	if !strings.EqualFold(head.Hash().String(), rev) {
		return fmt.Errorf("worktree: checkout failed")
	}
	return nil
}

func (st *gridState) repoCat(id, relPath string) ([]byte, error) {
	if !validGridID(id) {
		return nil, fmt.Errorf("repo: invalid id")
	}
	if err := validateRepoPath(relPath); err != nil {
		return nil, err
	}
	base, err := st.confinedWorktreePath(id)
	if err != nil {
		return nil, err
	}
	if info, err := os.Lstat(base); err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("repo: path escapes worktree")
	}
	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return nil, fmt.Errorf("repo: path escapes worktree")
	}
	clean := filepath.Clean(relPath)
	if err := validateRepoPath(clean); err != nil {
		return nil, err
	}
	full := filepath.Join(resolvedBase, clean)
	if !pathInside(resolvedBase, full) {
		return nil, fmt.Errorf("repo: path escapes worktree")
	}
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil || !pathInside(resolvedBase, resolved) {
		return nil, fmt.Errorf("repo: path escapes worktree")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, fmt.Errorf("repo: path escapes worktree")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("repo: path escapes worktree")
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("repo: path escapes worktree")
	}
	if info.Size() > gridMaxCat {
		return nil, fmt.Errorf("repo: file is too large")
	}
	data, err := io.ReadAll(io.LimitReader(file, gridMaxCat+1))
	if err != nil {
		return nil, fmt.Errorf("repo: path escapes worktree")
	}
	if int64(len(data)) > gridMaxCat {
		return nil, fmt.Errorf("repo: file is too large")
	}
	return data, nil
}

func validateRepoPath(relPath string) error {
	if relPath == "" || filepath.IsAbs(relPath) {
		return fmt.Errorf("repo: path escapes worktree")
	}
	parts := strings.FieldsFunc(relPath, func(r rune) bool { return r == '/' || r == '\\' })
	for _, part := range parts {
		if part == ".." {
			return fmt.Errorf("repo: path escapes worktree")
		}
	}
	clean := filepath.Clean(relPath)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) || filepath.IsAbs(clean) {
		return fmt.Errorf("repo: path escapes worktree")
	}
	return nil
}

func pathInside(base, target string) bool {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
}

func (st *gridState) confinedWorktreePath(id string) (string, error) {
	if !validGridID(id) {
		return "", fmt.Errorf("worktree: invalid id")
	}
	root, err := st.checkedScratchRoot()
	if err != nil {
		return "", err
	}
	dest := filepath.Join(root, id)
	if !pathInside(root, dest) {
		return "", fmt.Errorf("worktree: invalid id")
	}
	return dest, nil
}

// checkedScratchRoot returns the scratch root, creating it 0700 if missing.
// The root itself is never resolved through a symlink: it must be a real
// directory owned by the euid with mode 0700.
func (st *gridState) checkedScratchRoot() (string, error) {
	root := filepath.Clean(st.currentScratchRoot())
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("worktree: scratch root must be absolute")
	}
	if err := refuseWorldWritableAncestor(root); err != nil {
		return "", err
	}
	info, err := os.Lstat(root)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
			return "", fmt.Errorf("worktree: scratch root: %w", err)
		}
		if err := os.Mkdir(root, 0o700); err != nil && !os.IsExist(err) {
			return "", fmt.Errorf("worktree: scratch root: %w", err)
		}
		info, err = os.Lstat(root)
	}
	if err != nil {
		return "", fmt.Errorf("worktree: scratch root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("worktree: scratch root is a symlink")
	}
	if !info.IsDir() {
		return "", fmt.Errorf("worktree: scratch root is not a directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return "", fmt.Errorf("worktree: scratch root is not owned by this user")
	}
	if info.Mode().Perm() != 0o700 {
		return "", fmt.Errorf("worktree: scratch root mode must be 0700")
	}
	return root, nil
}

// refuseWorldWritableAncestor refuses a root whose nearest existing parent,
// once resolved, has a world-writable directory on its path. That covers
// /tmp, /var/tmp, and /dev/shm, where another user can plant the root.
func refuseWorldWritableAncestor(root string) error {
	parent := filepath.Dir(root)
	for {
		if _, err := os.Lstat(parent); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("worktree: scratch root: %w", err)
		}
		next := filepath.Dir(parent)
		if next == parent {
			break
		}
		parent = next
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return fmt.Errorf("worktree: scratch root: %w", err)
	}
	for dir := resolved; ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("worktree: scratch root: %w", err)
		}
		if info.Mode().Perm()&0o002 != 0 {
			return fmt.Errorf("worktree: scratch root is under a world-writable directory")
		}
		if filepath.Dir(dir) == dir {
			return nil
		}
	}
}

func ensureWorktreeDir(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("worktree: destination is a symlink")
		}
		if !info.IsDir() {
			return fmt.Errorf("worktree: destination is not a directory")
		}
		return os.Chmod(path, 0o700)
	}
	if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		if os.IsExist(err) {
			info, lerr := os.Lstat(path)
			if lerr != nil {
				return lerr
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("worktree: destination is a symlink")
			}
		}
		return err
	}
	return os.Chmod(path, 0o700)
}
