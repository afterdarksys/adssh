//go:build ee

package security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
)

func TestApprovalSink(t *testing.T) {
	id := "prompt-sink"
	sess := &sys.Session{ID: id, User: "u"}
	if err := sys.RegisterSession(sess); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(id) })
	buf := &safeBuf{}
	sess.SetPromptWriter(buf)
	if approvalSink(id) != buf {
		t.Fatal("writer")
	}
	if approvalSink("") != os.Stderr {
		t.Fatal("empty id")
	}
	if approvalSink("missing-session-id") != os.Stderr {
		t.Fatal("missing session")
	}
	sess.SetPromptWriter(nil)
	if approvalSink(id) != os.Stderr {
		t.Fatal("no writer")
	}
}

func TestRequestApprovalForSessionUsesPromptWriter(t *testing.T) {
	t.Setenv("ADSSH_4EYES_WEBHOOK", "")
	dir := t.TempDir()
	eng := &Engine{fourEyesDir: dir}
	id := "foureyes-prompt-1"
	sess := &sys.Session{ID: id, User: "requester"}
	if err := sys.RegisterSession(sess); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(id) })
	buf := &safeBuf{}
	sess.SetPromptWriter(buf)
	errCh := make(chan error, 1)
	go func() {
		errCh <- eng.RequestApprovalForSession("foureyes-probe-cmd", FourEyesRule{
			Approver: "other",
			TTL:      8,
		}, id)
	}()

	deadline := time.Now().Add(5 * time.Second)
	var requestID, pendingPath string
	for requestID == "" || pendingPath == "" {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatal("approval returned before the prompt")
			}
			t.Fatal("approval returned before the prompt")
		default:
		}
		text := buf.String()
		if i := strings.Index(text, "\nRequest: "); i >= 0 {
			rest := text[i+len("\nRequest: "):]
			if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
				requestID = rest[:nl]
			}
		}
		if j := strings.Index(buf.String(), "\nPending: "); j >= 0 {
			rest := buf.String()[j+len("\nPending: "):]
			if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
				pendingPath = rest[:nl]
			}
		}
		if requestID != "" && pendingPath != "" {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("prompt not visible")
		}
		time.Sleep(20 * time.Millisecond)
	}

	data, err := os.ReadFile(pendingPath)
	if err != nil {
		t.Fatal("pending file")
	}
	var pending FourEyesPending
	if err := json.Unmarshal(data, &pending); err != nil {
		t.Fatal("pending json")
	}
	if pending.Token == "" || pending.RequestID != requestID {
		t.Fatal("pending id")
	}
	if strings.Contains(buf.String(), pending.Token) {
		t.Fatal("token leaked")
	}
	if strings.Contains(buf.String(), "foureyes-probe-cmd") {
		t.Fatal("command in prompt")
	}

	approved := filepath.Join(eng.fourEyesApprovedDir(), requestID)
	if err := os.WriteFile(approved, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case err := <-errCh:
		if err != nil {
			if strings.Contains(err.Error(), pending.Token) {
				t.Fatal("token leaked")
			}
			t.Fatal("approval failed")
		}
	case <-timer.C:
		t.Fatal("approval did not finish")
	}
	if strings.Contains(buf.String(), pending.Token) {
		t.Fatal("token leaked")
	}
	if strings.Contains(buf.String(), "foureyes-probe-cmd") {
		t.Fatal("command in prompt")
	}
}
