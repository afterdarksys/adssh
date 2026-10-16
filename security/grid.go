package security

// Threats: a peer token, a remote flight, or a managed-agent checkout must
// not become root, skip policy, run git hooks, or read outside the scratch
// worktree. Membership tokens are compared in constant time and never logged.
// The listener is TLS 1.3 on a loopback address and is not the admin API.
// A parent allow does not bind the peer: each host evaluates policy locally
// and fails closed when no policy is loaded.
// Non-goals: this does not push policy, continue after a deny, or change the
// process uid. A frame lease_id does not authorize a command.

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
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"

	"github.com/afterdarksys/adssh/internal/sys"
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
)

var (
	gridMu      sync.Mutex
	gridState   *gridMembership
	scratchRoot = filepath.Join(os.TempDir(), "adssh-worktrees")

	commitHashPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
)

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
	engine    *Engine
	flights   map[string]*flightRecord
	agents    map[string]string
	worktrees map[string]string
	sessions  map[string]string
	serveErr  error
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
	Engine     *Engine
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
	fingerprint = fingerprintSecret(string(encoded))
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

func loadMembershipToken(path string) (string, []byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", nil, fmt.Errorf("grid: token file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", nil, fmt.Errorf("grid: token file is a symlink")
	}
	if info.Mode().Perm()&0o007 != 0 {
		return "", nil, fmt.Errorf("grid: token file is world-accessible")
	}
	if info.Size() > gridMaxTokenFile {
		return "", nil, fmt.Errorf("grid: token file is too large")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", nil, fmt.Errorf("grid: token file: %w", err)
	}
	defer file.Close()
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
	return roleNamePattern.MatchString(id)
}

func setScratchRoot(dir string) {
	gridMu.Lock()
	scratchRoot = dir
	gridMu.Unlock()
}

func currentScratchRoot() string {
	gridMu.Lock()
	defer gridMu.Unlock()
	return scratchRoot
}

func initGrid(id, tokenFile, tokenOut string) (string, string, error) {
	if tokenFile != "" && tokenOut != "" {
		return "", "", fmt.Errorf("grid: --token-file and --token-out cannot be combined")
	}
	if tokenFile == "" && tokenOut == "" {
		return "", "", fmt.Errorf("grid: --token-file or --token-out is required")
	}
	if id != "" && !validGridID(id) {
		return "", "", fmt.Errorf("grid: invalid id")
	}

	gridMu.Lock()
	already := gridState != nil
	gridMu.Unlock()
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

	gridMu.Lock()
	defer gridMu.Unlock()
	if gridState != nil {
		return "", "", fmt.Errorf("grid: already initialized")
	}
	gridState = &gridMembership{
		id:        id,
		tokenHash: hash,
		flights:   map[string]*flightRecord{},
		agents:    map[string]string{},
		worktrees: map[string]string{},
		sessions:  map[string]string{},
	}
	return id, fingerprint, nil
}

func gridStatus() (id, fingerprint, listen string, drained bool, flights int, err error) {
	gridMu.Lock()
	defer gridMu.Unlock()
	if gridState == nil {
		return "", "", "", false, 0, fmt.Errorf("grid: not initialized")
	}
	live := 0
	for _, flight := range gridState.flights {
		if flight.Status != "cancelled" {
			live++
		}
	}
	fp := ""
	if len(gridState.tokenHash) == sha256.Size {
		fp = hex.EncodeToString(gridState.tokenHash)
	}
	return gridState.id, fp, gridState.listenURL, gridState.drained, live, nil
}

func drainGrid() error {
	gridMu.Lock()
	defer gridMu.Unlock()
	if gridState == nil {
		return fmt.Errorf("grid: not initialized")
	}
	gridState.drained = true
	return nil
}

func listenGrid(listen, certFile, keyFile, tokenFile string, eng *Engine) (string, error) {
	if strings.TrimSpace(certFile) == "" || strings.TrimSpace(keyFile) == "" || strings.TrimSpace(tokenFile) == "" {
		return "", fmt.Errorf("grid: cert, key, and token file are required")
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("grid: listen address must be a loopback IP")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("grid: listen address must be a loopback IP")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return "", fmt.Errorf("grid: certificate: %w", err)
	}
	hexToken, hash, err := loadMembershipToken(tokenFile)
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

	gridMu.Lock()
	if gridState == nil {
		gridMu.Unlock()
		_ = ln.Close()
		return "", fmt.Errorf("grid: not initialized")
	}
	if gridState.listener != nil {
		gridMu.Unlock()
		_ = ln.Close()
		return "", fmt.Errorf("grid: already listening")
	}
	if len(gridState.tokenHash) == sha256.Size {
		if !gridTokenMatches(gridState.tokenHash, hexToken) {
			gridMu.Unlock()
			_ = ln.Close()
			return "", fmt.Errorf("grid: token mismatch")
		}
	} else {
		gridState.tokenHash = append([]byte(nil), hash...)
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(gridFlightHandler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	// tls.Listen already owns the handshake. ServeTLS would listen again.
	gridState.server = srv
	gridState.listener = ln
	gridState.listenURL = "https://" + ln.Addr().String()
	gridState.engine = eng
	listenURL := gridState.listenURL
	gridMu.Unlock()

	go func() {
		serveErr := srv.Serve(ln)
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			gridMu.Lock()
			if gridState != nil && gridState.server == srv {
				gridState.serveErr = serveErr
			}
			gridMu.Unlock()
		}
	}()
	return listenURL, nil
}

func resetGridState() {
	gridMu.Lock()
	var srv *http.Server
	var ln net.Listener
	if gridState != nil {
		srv = gridState.server
		ln = gridState.listener
	}
	gridMu.Unlock()

	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
	}
	if ln != nil {
		_ = ln.Close()
	}

	gridMu.Lock()
	var sessionIDs []string
	if gridState != nil {
		for id := range gridState.sessions {
			sessionIDs = append(sessionIDs, id)
		}
	}
	gridState = nil
	scratchRoot = filepath.Join(os.TempDir(), "adssh-worktrees")
	gridMu.Unlock()

	for _, id := range sessionIDs {
		if session := sys.GetSession(id); session != nil {
			session.ClearManagedAgent()
		}
		sys.UnregisterSession(id)
	}
}

func gridFlightHandler(w http.ResponseWriter, r *http.Request) {
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
	gridMu.Lock()
	var stored []byte
	var eng *Engine
	if gridState != nil {
		stored = append([]byte(nil), gridState.tokenHash...)
		eng = gridState.engine
	}
	gridMu.Unlock()
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
	result, callErr := dispatchFlightAction(eng, action, wire, true)
	if callErr != nil {
		writeGridHTTPError(w, callErr)
		return
	}
	writeFlightResult(w, result)
}

func dispatchFlightAction(eng *Engine, action string, wire flightWire, remote bool) (flightResult, error) {
	switch action {
	case "place":
		if eng == nil || !eng.PolicyLoaded() {
			return flightResult{}, gridErr(http.StatusForbidden, "policy_required")
		}
		if wire.TTLSeconds < 1 || wire.TTLSeconds > 86400 {
			return flightResult{}, gridErr(http.StatusBadRequest, "flight: ttl is invalid")
		}
		return placeFlight(placeOpts{
			FlightID:   wire.FlightID,
			AgentID:    wire.AgentID,
			WorktreeID: wire.WorktreeID,
			TTL:        time.Duration(wire.TTLSeconds) * time.Second,
			User:       gridPeerUser,
			Remote:     true,
			Engine:     eng,
		})
	case "rehearse", "rehearsal":
		if eng == nil || !eng.PolicyLoaded() {
			return flightResult{}, gridErr(http.StatusForbidden, "policy_required")
		}
		return rehearseFlight(eng, wire.FlightID, wire.Command, remote)
	case "cancel":
		return cancelFlight(wire.FlightID)
	case "status":
		return flightStatus(wire.FlightID)
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

func placeFlight(opts placeOpts) (flightResult, error) {
	if !validGridID(opts.FlightID) || !validGridID(opts.AgentID) || !validGridID(opts.WorktreeID) {
		return flightResult{}, gridErr(http.StatusBadRequest, "flight: invalid id")
	}
	if opts.TTL < time.Second || opts.TTL > 24*time.Hour {
		return flightResult{}, gridErr(http.StatusBadRequest, "flight: ttl is invalid")
	}
	user := opts.User
	if opts.Remote {
		user = gridPeerUser
	}
	if user == "" {
		return flightResult{}, gridErr(http.StatusBadRequest, "flight: user is required")
	}
	if opts.Engine == nil || !opts.Engine.PolicyLoaded() {
		return flightResult{}, gridErr(http.StatusForbidden, "policy_required")
	}

	gridMu.Lock()
	if gridState == nil {
		gridMu.Unlock()
		return flightResult{}, fmt.Errorf("grid: not initialized")
	}
	drained := gridState.drained
	gridMu.Unlock()
	if drained {
		return flightResult{}, gridErr(http.StatusConflict, "drained")
	}

	dir, err := confinedWorktreePath(opts.WorktreeID)
	if err != nil {
		return flightResult{}, err
	}
	if err := ensureWorktreeDir(dir); err != nil {
		return flightResult{}, fmt.Errorf("flight: worktree directory: %w", err)
	}

	now := time.Now().UTC()
	sessionID := "agent-" + opts.AgentID
	session := &sys.Session{ID: sessionID, User: user}
	session.BindManagedAgent(&sys.ManagedAgent{
		ID:        opts.AgentID,
		FlightID:  opts.FlightID,
		Worktree:  opts.WorktreeID,
		Allow:     agentAllowCopy(),
		ExpiresAt: now.Add(opts.TTL),
	})

	gridMu.Lock()
	if gridState == nil {
		gridMu.Unlock()
		return flightResult{}, fmt.Errorf("grid: not initialized")
	}
	if gridState.drained {
		gridMu.Unlock()
		return flightResult{}, gridErr(http.StatusConflict, "drained")
	}
	if _, ok := gridState.flights[opts.FlightID]; ok {
		gridMu.Unlock()
		return flightResult{}, gridErr(http.StatusConflict, "flight: duplicate id")
	}
	if _, ok := gridState.agents[opts.AgentID]; ok {
		gridMu.Unlock()
		return flightResult{}, gridErr(http.StatusConflict, "flight: duplicate id")
	}
	if _, ok := gridState.worktrees[opts.WorktreeID]; ok {
		gridMu.Unlock()
		return flightResult{}, gridErr(http.StatusConflict, "flight: duplicate id")
	}
	if _, ok := gridState.sessions[sessionID]; ok || sys.GetSession(sessionID) != nil {
		gridMu.Unlock()
		return flightResult{}, gridErr(http.StatusConflict, "flight: duplicate id")
	}
	live := 0
	for _, flight := range gridState.flights {
		if flight.Status != "cancelled" {
			live++
		}
	}
	if live >= gridMaxFlights {
		gridMu.Unlock()
		return flightResult{}, gridErr(http.StatusConflict, "flight: too many flights")
	}
	if err := sys.RegisterSession(session); err != nil {
		gridMu.Unlock()
		return flightResult{}, err
	}
	gridState.flights[opts.FlightID] = &flightRecord{
		ID:         opts.FlightID,
		AgentID:    opts.AgentID,
		WorktreeID: opts.WorktreeID,
		SessionID:  sessionID,
		User:       user,
		Status:     "placed",
		ExpiresAt:  now.Add(opts.TTL),
		Remote:     opts.Remote,
	}
	gridState.agents[opts.AgentID] = opts.FlightID
	gridState.worktrees[opts.WorktreeID] = opts.FlightID
	gridState.sessions[sessionID] = opts.FlightID
	gridMu.Unlock()
	return flightResult{Status: "placed", SessionID: sessionID, FlightID: opts.FlightID}, nil
}

func rehearseFlight(eng *Engine, flightID string, command []string, remote bool) (flightResult, error) {
	if !validGridID(flightID) {
		return flightResult{}, gridErr(http.StatusBadRequest, "flight: invalid id")
	}
	if err := validateFlightCommand(command); err != nil {
		return flightResult{}, err
	}
	if eng == nil || !eng.PolicyLoaded() {
		return flightResult{}, gridErr(http.StatusForbidden, "policy_required")
	}
	gridMu.Lock()
	if gridState == nil {
		gridMu.Unlock()
		return flightResult{}, fmt.Errorf("grid: not initialized")
	}
	rec := gridState.flights[flightID]
	if rec == nil {
		gridMu.Unlock()
		return flightResult{}, gridErr(http.StatusNotFound, "flight: not found")
	}
	sessionID := rec.SessionID
	status := rec.Status
	gridMu.Unlock()

	if !AgentCommandAllowed(command[0]) {
		reason := fmt.Sprintf("agent cannot run %q", command[0])
		rememberFlightDenial(flightID, reason, status)
		return flightResult{Status: "denied", Reason: reason, FlightID: flightID}, nil
	}
	if status == "cancelled" {
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

	pctx := BuildPolicyContext(command[0], command[1:], sessionID)
	if remote {
		pctx.User = gridPeerUser
		pctx.Groups = nil
		pctx.Elevation = nil
	}
	allowed, reason, err := eng.EvaluatePolicy(pctx)
	if err != nil {
		return flightResult{}, gridErr(http.StatusForbidden, "flight: policy evaluation failed")
	}
	if !allowed {
		if reason == "" {
			reason = "denied"
		}
		rememberFlightDenial(flightID, reason, status)
		return flightResult{Status: "denied", Reason: reason, FlightID: flightID}, nil
	}
	gridMu.Lock()
	if gridState != nil {
		if rec := gridState.flights[flightID]; rec != nil && rec.Status != "cancelled" {
			rec.Status = "rehearsed"
			rec.Reason = ""
		}
	}
	gridMu.Unlock()
	return flightResult{Status: "rehearsed", FlightID: flightID}, nil
}

func rememberFlightDenial(flightID, reason, previousStatus string) {
	if previousStatus == "cancelled" {
		return
	}
	gridMu.Lock()
	defer gridMu.Unlock()
	if gridState == nil {
		return
	}
	rec := gridState.flights[flightID]
	if rec == nil || rec.Status == "cancelled" {
		return
	}
	rec.Status = "denied"
	rec.Reason = reason
}

func cancelFlight(id string) (flightResult, error) {
	if !validGridID(id) {
		return flightResult{}, gridErr(http.StatusBadRequest, "flight: invalid id")
	}
	gridMu.Lock()
	if gridState == nil {
		gridMu.Unlock()
		return flightResult{}, fmt.Errorf("grid: not initialized")
	}
	rec := gridState.flights[id]
	if rec == nil {
		gridMu.Unlock()
		return flightResult{}, gridErr(http.StatusNotFound, "flight: not found")
	}
	sessionID := rec.SessionID
	rec.Status = "cancelled"
	rec.Reason = ""
	delete(gridState.agents, rec.AgentID)
	delete(gridState.worktrees, rec.WorktreeID)
	delete(gridState.sessions, sessionID)
	gridMu.Unlock()

	if session := sys.GetSession(sessionID); session != nil {
		session.ClearManagedAgent()
	}
	sys.UnregisterSession(sessionID)
	return flightResult{Status: "cancelled", FlightID: id}, nil
}

func flightStatus(id string) (flightResult, error) {
	if !validGridID(id) {
		return flightResult{}, gridErr(http.StatusBadRequest, "flight: invalid id")
	}
	gridMu.Lock()
	defer gridMu.Unlock()
	if gridState == nil {
		return flightResult{}, fmt.Errorf("grid: not initialized")
	}
	rec := gridState.flights[id]
	if rec == nil {
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

func listAgents() []flightRecord {
	gridMu.Lock()
	defer gridMu.Unlock()
	if gridState == nil {
		return nil
	}
	out := make([]flightRecord, 0, len(gridState.agents))
	for agentID, flightID := range gridState.agents {
		rec := gridState.flights[flightID]
		if rec == nil {
			out = append(out, flightRecord{AgentID: agentID, ID: flightID})
			continue
		}
		out = append(out, *rec)
	}
	return out
}

func postFlight(eng *Engine, opts flightClientOpts) (flightResult, error) {
	if opts.CAFile == "" {
		return flightResult{}, fmt.Errorf("flight: --host requires --ca")
	}
	parsed, err := url.Parse(opts.Host)
	if err != nil {
		return flightResult{}, fmt.Errorf("flight: host must be https")
	}
	if parsed.User != nil {
		return flightResult{}, fmt.Errorf("flight: credentials are rejected")
	}
	if parsed.Scheme != "https" {
		return flightResult{}, fmt.Errorf("flight: host must be https")
	}
	if opts.TokenFile == "" {
		return flightResult{}, fmt.Errorf("flight: --host requires --token-file")
	}
	action := opts.Action
	if action == "" {
		action = opts.Wire.Action
	}
	if action == "place" || action == "rehearse" || action == "rehearsal" {
		if eng == nil || !eng.PolicyLoaded() {
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
	serverName := opts.ServerName
	if serverName == "" {
		serverName = "localhost"
	}
	parsed.Path = "/v1/flight"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	if opts.Wire.Action == "" {
		opts.Wire.Action = action
	}
	payload, err := json.Marshal(opts.Wire)
	if err != nil {
		return flightResult{}, fmt.Errorf("flight: request failed")
	}
	client := &http.Client{
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
	req, err := http.NewRequest(http.MethodPost, parsed.String(), bytes.NewReader(payload))
	if err != nil {
		return flightResult{}, fmt.Errorf("flight: request failed")
	}
	req.Header.Set("Authorization", "Bearer "+hexToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return flightResult{}, err
	}
	defer resp.Body.Close()
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

func loadFlightCA(path string) (*x509.CertPool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("flight: ca file: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 && info.Size() > gridMaxCA {
		return nil, fmt.Errorf("flight: ca file is too large")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("flight: ca file: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, gridMaxCA+1))
	if err != nil {
		return nil, fmt.Errorf("flight: ca file: %w", err)
	}
	if int64(len(data)) > gridMaxCA {
		return nil, fmt.Errorf("flight: ca file is too large")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("flight: ca file has no certificates")
	}
	return pool, nil
}

func createWorktree(id string) (string, error) {
	if !validGridID(id) {
		return "", fmt.Errorf("worktree: invalid id")
	}
	path, err := confinedWorktreePath(id)
	if err != nil {
		return "", err
	}
	gridMu.Lock()
	if gridState == nil {
		gridMu.Unlock()
		return "", fmt.Errorf("grid: not initialized")
	}
	if _, ok := gridState.worktrees[id]; ok {
		gridMu.Unlock()
		return "", fmt.Errorf("worktree: duplicate id")
	}
	gridMu.Unlock()
	if err := ensureWorktreeDir(path); err != nil {
		return "", fmt.Errorf("worktree: directory: %w", err)
	}
	gridMu.Lock()
	defer gridMu.Unlock()
	if gridState == nil {
		return "", fmt.Errorf("grid: not initialized")
	}
	if _, ok := gridState.worktrees[id]; ok {
		return "", fmt.Errorf("worktree: duplicate id")
	}
	gridState.worktrees[id] = ""
	return path, nil
}

func destroyWorktree(id string) error {
	if !validGridID(id) {
		return fmt.Errorf("worktree: invalid id")
	}
	path, err := confinedWorktreePath(id)
	if err != nil {
		return err
	}
	gridMu.Lock()
	if gridState != nil {
		if flightID, ok := gridState.worktrees[id]; ok && flightID != "" {
			gridMu.Unlock()
			return fmt.Errorf("worktree: in use")
		}
		delete(gridState.worktrees, id)
	}
	gridMu.Unlock()
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
	return os.RemoveAll(path)
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

func checkoutWorktree(id, source, rev string) error {
	src, err := validateCheckoutSource(source)
	if err != nil {
		return err
	}
	if !commitHashPattern.MatchString(rev) {
		return fmt.Errorf("worktree: rev must be a 40-character commit hash")
	}
	dest, err := confinedWorktreePath(id)
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

func repoCat(id, relPath string) ([]byte, error) {
	if !validGridID(id) {
		return nil, fmt.Errorf("repo: invalid id")
	}
	if err := validateRepoPath(relPath); err != nil {
		return nil, err
	}
	base, err := confinedWorktreePath(id)
	if err != nil {
		return nil, err
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

func confinedWorktreePath(id string) (string, error) {
	if !validGridID(id) {
		return "", fmt.Errorf("worktree: invalid id")
	}
	root := filepath.Clean(currentScratchRoot())
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
		if err := os.MkdirAll(root, 0o700); err != nil {
			return "", err
		}
		if err := os.Chmod(root, 0o700); err != nil {
			return "", err
		}
		resolvedRoot, err = filepath.EvalSymlinks(root)
		if err != nil {
			return "", err
		}
	}
	dest := filepath.Join(resolvedRoot, id)
	if !pathInside(resolvedRoot, dest) {
		return "", fmt.Errorf("worktree: invalid id")
	}
	return dest, nil
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
