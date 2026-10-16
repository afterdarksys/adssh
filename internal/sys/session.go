package sys

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// OutputBroadcaster multiplexes a single stream of bytes to multiple io.Writers
type OutputBroadcaster struct {
	writers []io.Writer
	mu      sync.Mutex
}

func NewOutputBroadcaster(primary io.Writer) *OutputBroadcaster {
	return &OutputBroadcaster{
		writers: []io.Writer{primary},
	}
}

func (b *OutputBroadcaster) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, w := range b.writers {
		// Ignore write errors to secondary listeners so we don't crash the main session
		_, _ = w.Write(p) // best-effort
	}
	return len(p), nil
}

// PrimaryTerminalFile returns the broadcaster's primary writer when it is an
// *os.File attached to a real terminal, and nil otherwise. The PTY-backed
// foreground exec path uses this to recognize the interactive local session
// (primary = os.Stdout on a tty) and to skip everything else — SSH sessions
// (primary = an ssh channel), scripts, and pipes — where the primary is not a
// terminal-backed file.
func (b *OutputBroadcaster) PrimaryTerminalFile() *os.File {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.writers) == 0 {
		return nil
	}
	f, ok := b.writers[0].(*os.File)
	if !ok {
		return nil
	}
	if !term.IsTerminal(int(f.Fd())) {
		return nil
	}
	return f
}

func (b *OutputBroadcaster) AddListener(w io.Writer) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.writers = append(b.writers, w)
}

func (b *OutputBroadcaster) RemoveListener(w io.Writer) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, writer := range b.writers {
		if writer == w {
			b.writers = append(b.writers[:i], b.writers[i+1:]...)
			break
		}
	}
}

type Session struct {
	ID   string
	User string
	// Principals is set when the session is built. After RegisterSession
	// read and change it only through PrincipalList, AddPrincipal,
	// RemovePrincipal, SetIdentity, or Info, which hold mu.
	Principals []string
	PTYMaster  *os.File
	Out        *OutputBroadcaster
	CreatedAt  time.Time
	Recording  string

	mu             sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
	lastActive     time.Time
	currentCommand string
	terminated     bool
	recorder       *sessionRecorder
	elevation      *Elevation
	oidcProvider   string
	eligibleRoles  []string
	agentBinding   *ManagedAgent
	envOverlay     map[string]string
	dropPrivileges bool
	prompt         io.Writer
	identitySource string
	// controller names the admin key holding an rw attach, or "".
	controller string
}

// Identity sources. An empty source means User was set when the session was
// constructed by the code that registered it (the local shell, an SSH login).
// SetIdentity marks the session asserted. A caller that verified the new
// identity sets a stronger source after SetIdentity.
const (
	IdentitySourceAsserted     = "asserted"
	IdentitySourceDeviceLogin  = "device-login"
	IdentitySourceOIDCVerified = "oidc-verified"
)

// Per-entry ceilings. A session must not pin an unbounded overlay, and a
// value this large cannot be a credential we are willing to copy into a child.
const (
	maxEnvKeyLen         = 4 << 10
	maxEnvValueLen       = 256 << 10
	maxEnvOverlayEntries = 1024
)

type Elevation struct {
	Role      string    `json:"role"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ManagedAgent binds a session to one supervised cloud agent. The process
// uid does not change. ExpiresAt is the lease deadline.
type ManagedAgent struct {
	ID        string
	FlightID  string
	Worktree  string
	Allow     []string
	ExpiresAt time.Time
}

type SessionInfo struct {
	ID             string
	User           string
	Principals     []string
	CreatedAt      time.Time
	LastActive     time.Time
	CurrentCommand string
	Terminated     bool
	Recording      string
	Elevation      *Elevation
	OIDCProvider   string
	EligibleRoles  []string
	AgentID        string
}

func (s *Session) CancelCommand() {
	s.mu.RLock()
	cancel := s.cancel
	s.mu.RUnlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Session) Context() context.Context {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ctx
}

func (s *Session) SetContext(ctx context.Context, cancel context.CancelFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctx = ctx
	s.cancel = cancel
	s.touchLocked()
}

func (s *Session) SetCurrentCommand(command string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentCommand = command
	s.touchLocked()
}

func (s *Session) SetIdentity(user string, principals []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if user != "" {
		s.User = user
	}
	s.Principals = append([]string(nil), principals...)
	s.identitySource = IdentitySourceAsserted
	s.touchLocked()
}

// PrincipalList returns a copy of the session's principals. Read them
// through this, not the field, once the session is registered.
func (s *Session) PrincipalList() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.Principals...)
}

// AddPrincipal appends role unless it is present. It reports whether it
// was added.
func (s *Session) AddPrincipal(role string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.Principals {
		if p == role {
			return false
		}
	}
	s.Principals = append(append([]string(nil), s.Principals...), role)
	s.touchLocked()
	return true
}

// RemovePrincipal removes every copy of role. It reports whether one was
// present.
func (s *Session) RemovePrincipal(role string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := make([]string, 0, len(s.Principals))
	for _, p := range s.Principals {
		if p != role {
			kept = append(kept, p)
		}
	}
	if len(kept) == len(s.Principals) {
		return false
	}
	s.Principals = kept
	s.touchLocked()
	return true
}

// SetIdentitySource records how the current User was established.
func (s *Session) SetIdentitySource(source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identitySource = source
}

// IdentitySource returns how the current User was established. Empty means
// the registering code set it and nothing has renamed the session since.
func (s *Session) IdentitySource() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.identitySource
}

// ClaimController records name as the session's one rw attach controller.
// It reports false when another controller already holds the session.
func (s *Session) ClaimController(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.controller != "" || name == "" {
		return false
	}
	s.controller = name
	return true
}

// ReleaseController clears the controller when it is still name.
func (s *Session) ReleaseController(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.controller == name {
		s.controller = ""
	}
}

// Controller returns the admin key holding an rw attach, or "".
func (s *Session) Controller() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.controller
}

// SetOIDC records which OIDC audience established the session and which
// privileged roles that audience may elevate into. Eligible roles are not
// principals and do not elevate the session by themselves.
func (s *Session) SetOIDC(provider string, eligible []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.oidcProvider = provider
	s.eligibleRoles = append([]string(nil), eligible...)
	s.touchLocked()
}

// OIDC returns the provider name and a copy of the eligible privileged roles.
func (s *Session) OIDC() (string, []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.oidcProvider, append([]string(nil), s.eligibleRoles...)
}

// BindManagedAgent attaches a supervised cloud-agent lease to the session.
// A nil agent clears the binding.
func (s *Session) BindManagedAgent(agent *ManagedAgent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if agent == nil {
		s.agentBinding = nil
		s.touchLocked()
		return
	}
	copy := *agent
	copy.Allow = append([]string(nil), agent.Allow...)
	s.agentBinding = &copy
	s.touchLocked()
}

// ManagedAgent returns a copy of the cloud-agent binding, or nil.
func (s *Session) ManagedAgent() *ManagedAgent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.agentBinding == nil {
		return nil
	}
	copy := *s.agentBinding
	copy.Allow = append([]string(nil), s.agentBinding.Allow...)
	return &copy
}

// ClearManagedAgent removes the cloud-agent binding. The worktree is left
// in place for an explicit destroy.
func (s *Session) ClearManagedAgent() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agentBinding = nil
	s.touchLocked()
}

func (s *Session) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.touchLocked()
}

func (s *Session) Terminate() {
	s.mu.Lock()
	cancel := s.cancel
	ptyMaster := s.PTYMaster
	s.terminated = true
	s.touchLocked()
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if ptyMaster != nil {
		_ = ptyMaster.Close()
	}
}

func (s *Session) Info() SessionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var elevation *Elevation
	if active := s.activeElevationLocked(time.Now().UTC()); active != nil {
		copy := *active
		elevation = &copy
	}
	agentID := ""
	if s.agentBinding != nil {
		agentID = s.agentBinding.ID
	}
	return SessionInfo{
		ID:             s.ID,
		User:           s.User,
		Principals:     append([]string(nil), s.Principals...),
		CreatedAt:      s.CreatedAt,
		LastActive:     s.lastActive,
		CurrentCommand: s.currentCommand,
		Terminated:     s.terminated,
		Recording:      s.Recording,
		Elevation:      elevation,
		OIDCProvider:   s.oidcProvider,
		EligibleRoles:  append([]string(nil), s.eligibleRoles...),
		AgentID:        agentID,
	}
}

func (s *Session) ActivateElevation(role, reason string, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.elevation = &Elevation{Role: role, Reason: reason, ExpiresAt: expiresAt}
	s.touchLocked()
}

func (s *Session) DropElevation() *Elevation {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.elevation == nil {
		return nil
	}
	dropped := *s.elevation
	s.elevation = nil
	s.touchLocked()
	return &dropped
}

func (s *Session) ActiveElevation() *Elevation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeElevationLocked(time.Now().UTC())
}

func (s *Session) activeElevationLocked(now time.Time) *Elevation {
	if s.elevation == nil {
		return nil
	}
	if !now.Before(s.elevation.ExpiresAt) {
		s.elevation = nil
		return nil
	}
	copy := *s.elevation
	return &copy
}

func (s *Session) touchLocked() {
	s.lastActive = time.Now().UTC()
}

// Threats: session environment mutations must not call os.Setenv. An empty
// key, a key containing '=' or NUL, a value containing NUL, or an oversized
// key, value, or overlay is rejected and the previous overlay is left as it
// was. Lookup prefers the overlay, then the process environment.
func (s *Session) SetDropPrivileges(drop bool) {
	s.mu.Lock()
	s.dropPrivileges = drop
	s.mu.Unlock()
}

func (s *Session) DropPrivileges() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dropPrivileges
}

// SetPromptWriter is where four-eyes prompts for this session are written.
// The SSH listener sets it to that login's channel. A nil writer keeps the
// prompt on stderr.
func (s *Session) SetPromptWriter(w io.Writer) {
	s.mu.Lock()
	s.prompt = w
	s.mu.Unlock()
}

// PromptWriter returns the session prompt sink. The caller must not hold
// sessionsMu; this lock is only s.mu.
func (s *Session) PromptWriter() io.Writer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.prompt
}

func (s *Session) SetEnv(key, value string) error {
	if key == "" || strings.ContainsAny(key, "=\x00") {
		return fmt.Errorf("adssh: invalid environment key")
	}
	if strings.ContainsRune(value, 0) {
		return fmt.Errorf("adssh: invalid environment value")
	}
	if len(key) > maxEnvKeyLen || len(value) > maxEnvValueLen {
		return fmt.Errorf("adssh: environment assignment exceeds size limit")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.envOverlay == nil {
		s.envOverlay = make(map[string]string)
	}
	if _, exists := s.envOverlay[key]; !exists && len(s.envOverlay) >= maxEnvOverlayEntries {
		return fmt.Errorf("adssh: environment overlay is full")
	}
	s.envOverlay[key] = value
	return nil
}

func (s *Session) LookupEnv(key string) (string, bool) {
	s.mu.RLock()
	if s.envOverlay != nil {
		if value, ok := s.envOverlay[key]; ok {
			s.mu.RUnlock()
			return value, true
		}
	}
	s.mu.RUnlock()
	return os.LookupEnv(key)
}

func (s *Session) OverlayGet(key string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.envOverlay == nil {
		return "", false
	}
	value, ok := s.envOverlay[key]
	return value, ok
}

func (s *Session) EnvOverlay() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return copyOverlay(s.envOverlay)
}

func (s *Session) Environ() []string {
	s.mu.RLock()
	overlay := copyOverlay(s.envOverlay)
	s.mu.RUnlock()
	return mergeEnviron(os.Environ(), overlay)
}

func copyOverlay(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func mergeEnviron(base []string, overlay map[string]string) []string {
	out := make([]string, 0, len(base)+len(overlay))
	for _, kv := range base {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || name == "" {
			continue
		}
		if _, replaced := overlay[name]; replaced {
			continue
		}
		out = append(out, kv)
	}
	keys := make([]string, 0, len(overlay))
	for key := range overlay {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out = append(out, key+"="+overlay[key])
	}
	return out
}

// LastEnvWins collapses a merged environment so the last occurrence of a
// name is the only one. Empty entries left by an unset are dropped.
// Darwin and Linux getenv return the first occurrence, so a duplicate left
// in place would hide a later overlay or shell export.
func LastEnvWins(list []string) []string {
	index := make(map[string]int, len(list))
	out := make([]string, 0, len(list))
	for _, kv := range list {
		if kv == "" {
			continue
		}
		name, _, ok := strings.Cut(kv, "=")
		if !ok || name == "" {
			continue
		}
		if i, exists := index[name]; exists {
			out[i] = kv
			continue
		}
		index[name] = len(out)
		out = append(out, kv)
	}
	return out
}

var (
	globalSessions = make(map[string]*Session)
	sessionsMu     sync.RWMutex

	unregisterHooksMu sync.Mutex
	unregisterHooks   = map[uint64]func(id string){}
	unregisterHookSeq uint64
)

// OnSessionUnregister runs fn with the session id each time a registered
// session is unregistered, after it has left the table. Listener state
// keyed by session id (gateways, mirror grants) is released this way. The
// returned function removes the hook.
func OnSessionUnregister(fn func(id string)) (remove func()) {
	unregisterHooksMu.Lock()
	defer unregisterHooksMu.Unlock()
	unregisterHookSeq++
	key := unregisterHookSeq
	unregisterHooks[key] = fn
	return func() {
		unregisterHooksMu.Lock()
		delete(unregisterHooks, key)
		unregisterHooksMu.Unlock()
	}
}

func runUnregisterHooks(id string) {
	unregisterHooksMu.Lock()
	keys := make([]uint64, 0, len(unregisterHooks))
	for k := range unregisterHooks {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	hooks := make([]func(string), 0, len(keys))
	for _, k := range keys {
		hooks = append(hooks, unregisterHooks[k])
	}
	unregisterHooksMu.Unlock()
	for _, fn := range hooks {
		fn(id)
	}
}

// GenerateSessionID returns 128 random bits as 32 hex characters. A failure
// of the system random source panics rather than return a guessable id.
func GenerateSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("adssh: session id: %v", err))
	}
	return hex.EncodeToString(b)
}

// RegisterSession adds s to the session table. An id that is already
// registered is refused, so a later registration cannot replace the user or
// principals bound to a live session.
func RegisterSession(s *Session) error {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	if _, exists := globalSessions[s.ID]; exists {
		return fmt.Errorf("adssh: session id is already registered")
	}
	if sessionCapRefuse {
		return fmt.Errorf("adssh: session cap is invalid; refusing new sessions")
	}
	if sessionCap > 0 && uint64(len(globalSessions)) >= sessionCap {
		return fmt.Errorf("adssh: session cap of %d reached", sessionCap)
	}
	now := time.Now().UTC()
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	}
	s.mu.Lock()
	if s.lastActive.IsZero() {
		s.lastActive = now
	}
	s.mu.Unlock()
	if s.Out != nil && s.recorder == nil {
		if recorder, err := startSessionRecording(s); err == nil && recorder != nil {
			s.recorder = recorder
			s.Recording = recorder.path
			s.Out.AddListener(recorder)
		}
	}
	globalSessions[s.ID] = s
	return nil
}

func UnregisterSession(id string) {
	sessionsMu.Lock()
	session := globalSessions[id]
	delete(globalSessions, id)
	sessionsMu.Unlock()

	if session != nil && session.recorder != nil {
		if session.Out != nil {
			session.Out.RemoveListener(session.recorder)
		}
		_ = session.recorder.Close(session)
	}
	if session != nil {
		runUnregisterHooks(id)
	}
}

func GetSession(id string) *Session {
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	return globalSessions[id]
}

func ListSessions() []string {
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	var ids []string
	for id := range globalSessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func ListSessionInfo() []SessionInfo {
	sessionsMu.RLock()
	sessions := make([]*Session, 0, len(globalSessions))
	for _, session := range globalSessions {
		sessions = append(sessions, session)
	}
	sessionsMu.RUnlock()

	infos := make([]SessionInfo, 0, len(sessions))
	for _, session := range sessions {
		infos = append(infos, session.Info())
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].ID < infos[j].ID })
	return infos
}
