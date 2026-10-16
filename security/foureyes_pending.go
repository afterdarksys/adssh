package security

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
)

// Threats: a pending request is named by its request id, 32 hex characters
// from crypto/rand. The request id is a public handle: it is printed to the
// requester, listed by `4eyes pending` and GET /v1/approvals, and it is enough
// to name the request in approve or deny. It is not a credential, and neither
// is the legacy token field stored beside it, which is never displayed. What
// authorizes a decision is the approver's authenticated identity: a named
// admin key on HTTP, or a shell session whose user was not renamed at runtime
// (see shellApprover). The requester cannot decide their own request and a
// rule's configured approver must match. A decision claims the pending file by
// atomic rename, so only one approve or deny can win, and it is written to the
// audit chain before the marker. A marker write that fails after the audit
// event is reverted in the chain and the claim is restored; a claim left by a
// crash is swept after its TTL and logged. This does not stop a process running as the
// OS account that owns the four-eyes directory from writing a marker itself.

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func (e *Engine) createFourEyesPending(cmd string, rule FourEyesRule, sessionID string) (FourEyesPending, string, error) {
	if err := checkRequesterIdentity(sessionID); err != nil {
		return FourEyesPending{}, "", err
	}
	requester := approvalActor(sessionID)
	if requester == "" {
		requester = "unknown"
	}
	return e.createFourEyesPendingAs(cmd, rule, requester)
}

// createFourEyesPendingAs writes a pending request whose requester the
// caller has already authenticated (a named admin key for snoop).
func (e *Engine) createFourEyesPendingAs(cmd string, rule FourEyesRule, requester string) (FourEyesPending, string, error) {
	requestID, err := randomHex(16)
	if err != nil {
		return FourEyesPending{}, "", fmt.Errorf("foureyes: generate request id: %w", err)
	}
	token, err := randomHex(16)
	if err != nil {
		return FourEyesPending{}, "", fmt.Errorf("foureyes: generate token: %w", err)
	}
	hostname, _ := os.Hostname()
	pending := FourEyesPending{
		Token:     token,
		RequestID: requestID,
		Command:   cmd,
		Requester: requester,
		Hostname:  hostname,
		Timestamp: timeNowRFC3339(),
		Rule:      rule,
	}
	data, err := json.MarshalIndent(pending, "", "  ")
	if err != nil {
		return FourEyesPending{}, "", fmt.Errorf("foureyes: marshal pending: %w", err)
	}
	pendingFile := filepath.Join(e.fourEyesPendingDir(), requestID+".json")
	file, err := os.OpenFile(pendingFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return FourEyesPending{}, "", fmt.Errorf("foureyes: write pending: %w", err)
	}
	_, writeErr := file.Write(data)
	chmodErr := file.Chmod(0o600)
	closeErr := file.Close()
	if writeErr != nil {
		return FourEyesPending{}, "", fmt.Errorf("foureyes: write pending: %w", writeErr)
	}
	if chmodErr != nil {
		return FourEyesPending{}, "", fmt.Errorf("foureyes: write pending: %w", chmodErr)
	}
	if closeErr != nil {
		return FourEyesPending{}, "", fmt.Errorf("foureyes: write pending: %w", closeErr)
	}
	info, err := os.Stat(pendingFile)
	if err != nil {
		return FourEyesPending{}, "", fmt.Errorf("foureyes: write pending: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return FourEyesPending{}, "", fmt.Errorf("foureyes: pending request is group or world readable")
	}
	return pending, pendingFile, nil
}

// checkRequesterIdentity refuses a request from a session whose user was
// renamed at runtime without verification. Otherwise alice could rename her
// session to carol, request, and approve the request as alice.
func checkRequesterIdentity(sessionID string) error {
	if sessionID == "" {
		return nil
	}
	session := sys.GetSession(sessionID)
	if session == nil {
		return nil
	}
	switch source := session.IdentitySource(); source {
	case "", sys.IdentitySourceOIDCVerified:
		return nil
	default:
		return fmt.Errorf("foureyes: identity set by %s cannot request approval; reconnect or import a verified identity", source)
	}
}

func timeNowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func (e *Engine) locatePending(presented string) (FourEyesPending, string, string, error) {
	direct := filepath.Join(e.fourEyesPendingDir(), presented+".json")
	data, err := os.ReadFile(direct)
	if err == nil {
		var pending FourEyesPending
		if err := json.Unmarshal(data, &pending); err != nil {
			return FourEyesPending{}, "", "", fmt.Errorf("foureyes: parse pending request: %w", err)
		}
		marker := strings.TrimSuffix(filepath.Base(direct), ".json")
		if pending.Token == "" || constantTimeEqual(pending.Token, presented) || pending.RequestID == presented {
			return pending, direct, marker, nil
		}
		return FourEyesPending{}, "", "", fmt.Errorf("foureyes: pending request token mismatch")
	}
	if !os.IsNotExist(err) {
		return FourEyesPending{}, "", "", fmt.Errorf("foureyes: read pending request: %w", err)
	}
	entries, err := os.ReadDir(e.fourEyesPendingDir())
	if err != nil {
		return FourEyesPending{}, "", "", fmt.Errorf("foureyes: read pending request: %w", err)
	}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		path := filepath.Join(e.fourEyesPendingDir(), ent.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var pending FourEyesPending
		if err := json.Unmarshal(data, &pending); err != nil {
			continue
		}
		if pending.Token == "" || !constantTimeEqual(pending.Token, presented) {
			continue
		}
		marker := strings.TrimSuffix(ent.Name(), ".json")
		return pending, path, marker, nil
	}
	return FourEyesPending{}, "", "", fmt.Errorf("foureyes: read pending request: %w", os.ErrNotExist)
}

func formatApprovalPrompt(pendingFile, requestID, required string) string {
	if required == "" {
		required = "any distinct approver"
	}
	return fmt.Sprintf("\n4-eyes required.\nPending: %s\nRequest: %s\nRequired approver: %s\nRun: 4eyes approve %s\n\n",
		pendingFile, requestID, required, requestID)
}

func pendingPublicID(pending FourEyesPending) string {
	if pending.RequestID != "" {
		return pending.RequestID
	}
	return pending.Token
}

func commandHead(cmd string) string {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
