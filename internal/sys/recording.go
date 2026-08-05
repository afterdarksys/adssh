package sys

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type sessionRecorder struct {
	mu   sync.Mutex
	file *os.File
	path string
}

type recordingEvent struct {
	Timestamp  string   `json:"ts"`
	SessionID  string   `json:"session_id"`
	User       string   `json:"user,omitempty"`
	Principals []string `json:"principals,omitempty"`
	Type       string   `json:"type"`
	Data       string   `json:"data_b64,omitempty"`
}

func startSessionRecording(s *Session) (*sessionRecorder, error) {
	dir := sessionRecordingDir()
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, s.ID+".jsonl")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	rec := &sessionRecorder{file: file, path: path}
	if err := rec.writeEvent(recordingEvent{
		SessionID:  s.ID,
		User:       s.User,
		Principals: append([]string(nil), s.Principals...),
		Type:       "start",
	}); err != nil {
		_ = file.Close()
		return nil, err
	}
	return rec, nil
}

func sessionRecordingDir() string {
	if dir := os.Getenv("ADSSH_RECORD_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".adssh", "recordings")
}

func (r *sessionRecorder) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	err := r.writeEvent(recordingEvent{
		Type: "output",
		Data: base64.StdEncoding.EncodeToString(p),
	})
	return len(p), err
}

func (r *sessionRecorder) Close(s *Session) error {
	if r == nil {
		return nil
	}
	if err := r.writeEvent(recordingEvent{
		SessionID: s.ID,
		User:      s.User,
		Type:      "end",
	}); err != nil {
		_ = r.file.Close()
		return err
	}
	return r.file.Close()
}

func (r *sessionRecorder) writeEvent(event recordingEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(r.file, string(data)); err != nil {
		return err
	}
	return nil
}
