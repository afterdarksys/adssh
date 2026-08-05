package sys

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegisteredSessionRecordsOutputJSONL(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ADSSH_RECORD_DIR", dir)
	var primary bytes.Buffer
	session := &Session{
		ID:   "recording-test",
		User: "alice",
		Out:  NewOutputBroadcaster(&primary),
	}
	RegisterSession(session)
	_, _ = session.Out.Write([]byte("hello\r\n"))
	UnregisterSession(session.ID)

	path := filepath.Join(dir, "recording-test.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("recording lines = %d, want 3: %s", len(lines), data)
	}
	var start, output, end recordingEvent
	if err := json.Unmarshal([]byte(lines[0]), &start); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &output); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[2]), &end); err != nil {
		t.Fatal(err)
	}
	if start.Type != "start" || start.SessionID != "recording-test" || start.User != "alice" {
		t.Fatalf("start event = %#v", start)
	}
	decoded, err := base64.StdEncoding.DecodeString(output.Data)
	if err != nil {
		t.Fatal(err)
	}
	if output.Type != "output" || string(decoded) != "hello\r\n" {
		t.Fatalf("output event = %#v decoded=%q", output, decoded)
	}
	if end.Type != "end" || end.SessionID != "recording-test" {
		t.Fatalf("end event = %#v", end)
	}
	if primary.String() != "hello\r\n" {
		t.Fatalf("primary output = %q", primary.String())
	}
}
