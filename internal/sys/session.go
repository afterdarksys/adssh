package sys

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"sort"
	"sync"
	"time"
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
	ID         string
	User       string
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
}

type Elevation struct {
	Role      string    `json:"role"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
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

var (
	globalSessions = make(map[string]*Session)
	sessionsMu     sync.RWMutex
)

// GenerateSessionID creates a random 8-character hex string
func GenerateSessionID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func RegisterSession(s *Session) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
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
