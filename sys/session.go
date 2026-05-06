package sys

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"sync"
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
		w.Write(p)
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
	ID        string
	PTYMaster *os.File
	Out       *OutputBroadcaster
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
	globalSessions[s.ID] = s
}

func UnregisterSession(id string) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	delete(globalSessions, id)
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
	return ids
}
