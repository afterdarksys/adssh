package security

// Threats: a peer token, a remote flight, or a managed-agent checkout must
// not become root, skip policy, run git hooks, or read outside the scratch
// worktree. Membership tokens are compared in constant time and never logged;
// the token file is opened with O_NOFOLLOW and refused unless fstat shows a
// regular file with no group or other bits. The listener is TLS 1.3 on a
// loopback address and is not the admin API. A parent allow does not bind the
// peer: each host evaluates policy locally and fails closed when no policy is
// loaded. A remote peer may cancel or read only flights it placed. Flights
// past their TTL are cancelled and their agent sessions released.
// The scratch root lives under the XDG data dir, never os.TempDir(). It must
// be a real directory (not a symlink) owned by the euid with mode 0700, and no
// ancestor may be world-writable; destroy removes only worktree ids this grid
// recorded. An agent checkout clones only the source the operator bound to
// its flight at place time.
// Non-goals: this does not push policy, continue after a deny, or change the
// process uid. A frame lease_id does not authorize a command. It does not
// defend against another process running as the same uid.

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

	// gridCancelledRetention is how long a cancelled flight stays readable.
	gridCancelledRetention = time.Hour
	// worktreeDestroying reserves a worktree id while destroy removes it, so
	// place cannot bind it in the meantime.
	worktreeDestroying = "\x00destroying"
)

var (
	gridMu      sync.Mutex
	gridState   *gridMembership
	scratchRoot = defaultScratchRoot()

	// gridReapInterval is how often a listening grid cancels expired flights.
	gridReapInterval = 30 * time.Second

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
	Engine     *Engine
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
	return roleNamePattern.MatchString(id)
}

// defaultScratchRoot keeps worktrees under the adssh XDG data dir. There is no
// XDG state helper in internal/config, so the data dir is the closest one.
func defaultScratchRoot() string {
	return filepath.Join(config.XDGDataHome(), "worktrees")
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
	reapExpiredFlights(time.Now())
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
		Handler:           http.HandlerFunc(gridFlightHandler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	stop := make(chan struct{})
	listenURL, err := installGridServer(srv, ln, eng, hexToken, hash, stop)
	if err != nil {
		if closeErr := ln.Close(); closeErr != nil {
			return "", errors.Join(err, closeErr)
		}
		return "", err
	}

	go runGridReaper(stop, gridReapInterval)
	go func() {
		// tls.Listen already owns the handshake. ServeTLS would listen again.
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
func installGridServer(srv *http.Server, ln net.Listener, eng *Engine, hexToken string, hash []byte, stop chan struct{}) (string, error) {
	gridMu.Lock()
	defer gridMu.Unlock()
	if gridState == nil {
		return "", fmt.Errorf("grid: not initialized")
	}
	if gridState.listener != nil {
		return "", fmt.Errorf("grid: already listening")
	}
	if len(gridState.tokenHash) == sha256.Size {
		if !gridTokenMatches(gridState.tokenHash, hexToken) {
			return "", fmt.Errorf("grid: token mismatch")
		}
	} else {
		gridState.tokenHash = append([]byte(nil), hash...)
	}
	gridState.server = srv
	gridState.listener = ln
	gridState.listenURL = "https://" + ln.Addr().String()
	gridState.engine = eng
	gridState.stopReap = stop
	return gridState.listenURL, nil
}

// runGridReaper cancels expired flights on every tick until stop closes.
func runGridReaper(stop <-chan struct{}, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			reapExpiredFlights(now)
		}
	}
}

// reapExpiredFlights cancels every live flight past its TTL, releases its
// agent session, and forgets cancelled flights older than the retention.
func reapExpiredFlights(now time.Time) {
	gridMu.Lock()
	if gridState == nil {
		gridMu.Unlock()
		return
	}
	var released []string
	for id, rec := range gridState.flights {
		if rec.Status == "cancelled" {
			if now.Sub(rec.CancelledAt) > gridCancelledRetention {
				delete(gridState.flights, id)
			}
			continue
		}
		if !now.Before(rec.ExpiresAt) {
			released = append(released, cancelFlightLocked(rec, "lease expired", now))
		}
	}
	gridMu.Unlock()
	releaseAgentSessions(released)
}

// cancelFlightLocked marks rec cancelled and frees its agent and worktree
// ids. The caller holds gridMu and must release the returned session.
func cancelFlightLocked(rec *flightRecord, reason string, now time.Time) string {
	rec.Status = "cancelled"
	rec.Reason = reason
	rec.CancelledAt = now
	if gridState.agents[rec.AgentID] == rec.ID {
		delete(gridState.agents, rec.AgentID)
	}
	if gridState.worktrees[rec.WorktreeID] == rec.ID {
		// The directory stays, so the id stays recorded and destroyable.
		gridState.worktrees[rec.WorktreeID] = ""
	}
	delete(gridState.sessions, rec.SessionID)
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

func resetGridState() {
	gridMu.Lock()
	var srv *http.Server
	var ln net.Listener
	if gridState != nil {
		srv = gridState.server
		ln = gridState.listener
		if gridState.stopReap != nil {
			close(gridState.stopReap)
			gridState.stopReap = nil
		}
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
	scratchRoot = defaultScratchRoot()
	gridMu.Unlock()

	releaseAgentSessions(sessionIDs)
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
	case "cancel", "status":
		if eng == nil || !eng.PolicyLoaded() {
			return flightResult{}, gridErr(http.StatusForbidden, "policy_required")
		}
		if action == "cancel" {
			return cancelFlight(wire.FlightID, remote)
		}
		return flightStatus(wire.FlightID, remote)
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
	user, source, err := validatePlaceOpts(opts)
	if err != nil {
		return flightResult{}, err
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
	now := time.Now().UTC()
	reapExpiredFlights(now)

	dir, err := confinedWorktreePath(opts.WorktreeID)
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
		Allow:     agentAllowCopy(),
		ExpiresAt: rec.ExpiresAt,
	})
	if err := registerFlight(rec, session, now); err != nil {
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
	if opts.Engine == nil || !opts.Engine.PolicyLoaded() {
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
func registerFlight(rec *flightRecord, session *sys.Session, now time.Time) error {
	gridMu.Lock()
	defer gridMu.Unlock()
	if gridState == nil {
		return fmt.Errorf("grid: not initialized")
	}
	if gridState.drained {
		return gridErr(http.StatusConflict, "drained")
	}
	_, flightTaken := gridState.flights[rec.ID]
	_, agentTaken := gridState.agents[rec.AgentID]
	_, sessionTaken := gridState.sessions[rec.SessionID]
	if flightTaken || agentTaken || sessionTaken || gridState.worktrees[rec.WorktreeID] != "" ||
		sys.GetSession(rec.SessionID) != nil {
		return gridErr(http.StatusConflict, "flight: duplicate id")
	}
	live := 0
	for _, flight := range gridState.flights {
		if flight.Status != "cancelled" && now.Before(flight.ExpiresAt) {
			live++
		}
	}
	if live >= gridMaxFlights {
		return gridErr(http.StatusConflict, "flight: too many flights")
	}
	if err := sys.RegisterSession(session); err != nil {
		return err
	}
	gridState.flights[rec.ID] = rec
	gridState.agents[rec.AgentID] = rec.ID
	gridState.worktrees[rec.WorktreeID] = rec.ID
	gridState.sessions[rec.SessionID] = rec.ID
	return nil
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

	pctx := eng.buildPolicyContext(command[0], command[1:], sessionID)
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

// cancelFlight cancels a flight. remoteOnly is set for a grid peer, which
// may cancel only flights a peer placed; a local flight reads as not found.
func cancelFlight(id string, remoteOnly bool) (flightResult, error) {
	if !validGridID(id) {
		return flightResult{}, gridErr(http.StatusBadRequest, "flight: invalid id")
	}
	gridMu.Lock()
	if gridState == nil {
		gridMu.Unlock()
		return flightResult{}, fmt.Errorf("grid: not initialized")
	}
	rec := gridState.flights[id]
	if rec == nil || (remoteOnly && !rec.Remote) {
		gridMu.Unlock()
		return flightResult{}, gridErr(http.StatusNotFound, "flight: not found")
	}
	sessionID := cancelFlightLocked(rec, "", time.Now())
	gridMu.Unlock()

	releaseAgentSessions([]string{sessionID})
	return flightResult{Status: "cancelled", FlightID: id}, nil
}

// flightStatus reads a flight. remoteOnly hides local flights from a peer.
func flightStatus(id string, remoteOnly bool) (flightResult, error) {
	if !validGridID(id) {
		return flightResult{}, gridErr(http.StatusBadRequest, "flight: invalid id")
	}
	gridMu.Lock()
	defer gridMu.Unlock()
	if gridState == nil {
		return flightResult{}, fmt.Errorf("grid: not initialized")
	}
	rec := gridState.flights[id]
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
	target, err := flightEndpoint(opts)
	if err != nil {
		return flightResult{}, err
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

// destroyWorktree removes a worktree this grid recorded and that no live
// flight holds. An unrecorded id is refused even if the directory exists.
func destroyWorktree(id string) error {
	if !validGridID(id) {
		return fmt.Errorf("worktree: invalid id")
	}
	gridMu.Lock()
	if gridState == nil {
		gridMu.Unlock()
		return fmt.Errorf("grid: not initialized")
	}
	flightID, ok := gridState.worktrees[id]
	if !ok {
		gridMu.Unlock()
		return fmt.Errorf("worktree: not found")
	}
	if flightID != "" {
		gridMu.Unlock()
		return fmt.Errorf("worktree: in use")
	}
	gridState.worktrees[id] = worktreeDestroying
	gridMu.Unlock()

	err := removeWorktreeDir(id)
	gridMu.Lock()
	if gridState != nil && gridState.worktrees[id] == worktreeDestroying {
		if err == nil {
			delete(gridState.worktrees, id)
		} else {
			gridState.worktrees[id] = ""
		}
	}
	gridMu.Unlock()
	return err
}

func removeWorktreeDir(id string) error {
	path, err := confinedWorktreePath(id)
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
func agentCheckoutSource(agent *sys.ManagedAgent, from string) (string, error) {
	gridMu.Lock()
	var rec *flightRecord
	if gridState != nil {
		rec = gridState.flights[agent.FlightID]
	}
	bound := ""
	if rec != nil && rec.AgentID == agent.ID && rec.Status != "cancelled" {
		bound = rec.Source
	}
	gridMu.Unlock()
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

func confinedWorktreePath(id string) (string, error) {
	if !validGridID(id) {
		return "", fmt.Errorf("worktree: invalid id")
	}
	root, err := checkedScratchRoot()
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
func checkedScratchRoot() (string, error) {
	root := filepath.Clean(currentScratchRoot())
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
