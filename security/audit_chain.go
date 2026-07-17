package security

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ChainEntry is one line in the audit ledger.
// It is serialised as a single JSON object per line.
type ChainEntry struct {
	Seq       int64   `json:"seq"`
	Timestamp string  `json:"ts"`                  // RFC3339Nano UTC
	SessionID string  `json:"session"`
	User      string  `json:"user"`
	Hostname  string  `json:"host"`
	Type      string  `json:"type"`                // "cmd", "policy", "event", "4eyes", "cm"
	Command   string  `json:"cmd,omitempty"`
	Source    string  `json:"source,omitempty"`
	Allowed   *bool   `json:"allowed,omitempty"`
	Reason    string  `json:"reason,omitempty"`
	ChangeID  string  `json:"change_id,omitempty"` // CM ticket if set
	PrevHash  string  `json:"prev_hash"`
	Hash      string  `json:"hash"`
}

// chainEntryForHash is ChainEntry without the Hash field, used for HMAC computation.
type chainEntryForHash struct {
	Seq       int64   `json:"seq"`
	Timestamp string  `json:"ts"`
	SessionID string  `json:"session"`
	User      string  `json:"user"`
	Hostname  string  `json:"host"`
	Type      string  `json:"type"`
	Command   string  `json:"cmd,omitempty"`
	Source    string  `json:"source,omitempty"`
	Allowed   *bool   `json:"allowed,omitempty"`
	Reason    string  `json:"reason,omitempty"`
	ChangeID  string  `json:"change_id,omitempty"`
	PrevHash  string  `json:"prev_hash"`
}

// InitChain sets the ledger path, loads or creates the HMAC key, and sets the session ID.
func (e *Engine) InitChain(ledgerPath, keyPath, sessionID string) {
	e.chainMu.Lock()
	defer e.chainMu.Unlock()

	e.chainPath = ledgerPath
	e.chainSession = sessionID

	key, err := loadOrCreateChainKey(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit chain: failed to load/create key: %v\n", err)
		return
	}
	e.chainKey = key
}

// InitChain sets the ledger path, loads or creates the HMAC key, and sets the session ID.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func InitChain(ledgerPath, keyPath, sessionID string) {
	defaultEngine.InitChain(ledgerPath, keyPath, sessionID)
}

// loadOrCreateChainKey reads the HMAC key from path, or generates and writes a new one.
func loadOrCreateChainKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil && len(data) == 32 {
		return data, nil
	}

	// Generate new 32-byte key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create key dir: %v", err)
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		return nil, fmt.Errorf("write key: %v", err)
	}
	return key, nil
}

// computeHash computes the HMAC-SHA256 of prev + "\n" + JSON(entry without Hash).
func computeHash(key []byte, prev string, entry ChainEntry) string {
	withoutHash := chainEntryForHash{
		Seq:       entry.Seq,
		Timestamp: entry.Timestamp,
		SessionID: entry.SessionID,
		User:      entry.User,
		Hostname:  entry.Hostname,
		Type:      entry.Type,
		Command:   entry.Command,
		Source:    entry.Source,
		Allowed:   entry.Allowed,
		Reason:    entry.Reason,
		ChangeID:  entry.ChangeID,
		PrevHash:  entry.PrevHash,
	}
	entryJSON, _ := json.Marshal(withoutHash)

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(prev))
	mac.Write([]byte("\n"))
	mac.Write(entryJSON)
	return hex.EncodeToString(mac.Sum(nil))
}

// currentUser returns the current user from env vars.
func currentUser() string {
	if u := os.Getenv("ADSSH_USER"); u != "" {
		return u
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return os.Getenv("LOGNAME")
}

// currentHostname returns the current hostname.
func currentHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

// readLastChainLine reads only the last non-empty line from the ledger file.
// Returns prevHash and nextSeq.
func readLastChainLine(path string) (prevHash string, nextSeq int64) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0
	}
	defer f.Close()

	var lastLine string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if line := scanner.Text(); strings.TrimSpace(line) != "" {
			lastLine = line
		}
	}

	if lastLine == "" {
		return "", 0
	}

	var entry ChainEntry
	if err := json.Unmarshal([]byte(lastLine), &entry); err != nil {
		return "", 0
	}
	return entry.Hash, entry.Seq + 1
}

// AppendChain appends a new entry to the HMAC chain ledger.
// It is a no-op if InitChain has not been called.
func (e *Engine) AppendChain(entry ChainEntry) {
	e.chainMu.Lock()
	defer e.chainMu.Unlock()

	if e.chainPath == "" || e.chainKey == nil {
		return
	}

	prevHash, nextSeq := readLastChainLine(e.chainPath)

	entry.Seq = nextSeq
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	if entry.SessionID == "" {
		entry.SessionID = e.chainSession
	}
	if entry.User == "" {
		entry.User = currentUser()
	}
	if entry.Hostname == "" {
		entry.Hostname = currentHostname()
	}
	entry.PrevHash = prevHash
	entry.Hash = computeHash(e.chainKey, prevHash, entry)

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	if err := os.MkdirAll(filepath.Dir(e.chainPath), 0700); err != nil {
		return
	}

	f, err := os.OpenFile(e.chainPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(data)
	f.Write([]byte("\n"))
}

// AppendChain appends a new entry to the HMAC chain ledger.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func AppendChain(entry ChainEntry) {
	defaultEngine.AppendChain(entry)
}

// VerifyChain reads every line of the ledger and recomputes each hash.
// Returns ok=true if the chain is intact, otherwise ok=false with the
// sequence number of the first broken link.
func (e *Engine) VerifyChain(path string) (ok bool, badSeq int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return false, -1, fmt.Errorf("open ledger: %v", err)
	}
	defer f.Close()

	e.chainMu.Lock()
	key := e.chainKey
	e.chainMu.Unlock()

	if key == nil {
		return false, -1, fmt.Errorf("chain not initialised")
	}

	var prev string
	var lineNum int64

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var entry ChainEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return false, lineNum, fmt.Errorf("parse error at seq ~%d: %v", lineNum, err)
		}

		storedHash := entry.Hash
		expected := computeHash(key, prev, entry)
		if storedHash != expected {
			return false, entry.Seq, nil
		}
		prev = storedHash
		lineNum = entry.Seq
	}

	if err := scanner.Err(); err != nil {
		return false, lineNum, fmt.Errorf("scan error: %v", err)
	}
	return true, -1, nil
}

// VerifyChain reads every line of the ledger and recomputes each hash.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func VerifyChain(path string) (ok bool, badSeq int64, err error) {
	return defaultEngine.VerifyChain(path)
}

// ExportChain reads the ledger, filters by timestamp range, and outputs JSON or CSV.
// It reads only the file at path and holds no engine state, but is exposed as an
// Engine method for API symmetry.
func (e *Engine) ExportChain(path, format, since, until string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ledger: %v", err)
	}
	defer f.Close()

	var sinceT, untilT time.Time
	if since != "" {
		sinceT, err = time.Parse("2006-01-02", since)
		if err != nil {
			return nil, fmt.Errorf("invalid --since: %v", err)
		}
	}
	if until != "" {
		untilT, err = time.Parse("2006-01-02", until)
		if err != nil {
			return nil, fmt.Errorf("invalid --until: %v", err)
		}
		untilT = untilT.Add(24 * time.Hour) // inclusive of the until date
	}

	var entries []ChainEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		var entry ChainEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, entry.Timestamp)
		if err != nil {
			ts, _ = time.Parse(time.RFC3339, entry.Timestamp)
		}
		if !sinceT.IsZero() && ts.Before(sinceT) {
			continue
		}
		if !untilT.IsZero() && !ts.Before(untilT) {
			continue
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan: %v", err)
	}

	switch strings.ToLower(format) {
	case "csv":
		var sb strings.Builder
		w := csv.NewWriter(&sb)
		_ = w.Write([]string{"seq", "ts", "session", "user", "host", "type", "cmd", "source", "allowed", "reason", "change_id", "prev_hash", "hash"})
		for _, e := range entries {
			allowed := ""
			if e.Allowed != nil {
				if *e.Allowed {
					allowed = "true"
				} else {
					allowed = "false"
				}
			}
			_ = w.Write([]string{
				fmt.Sprintf("%d", e.Seq),
				e.Timestamp,
				e.SessionID,
				e.User,
				e.Hostname,
				e.Type,
				e.Command,
				e.Source,
				allowed,
				e.Reason,
				e.ChangeID,
				e.PrevHash,
				e.Hash,
			})
		}
		w.Flush()
		return []byte(sb.String()), nil

	default: // json
		return json.MarshalIndent(entries, "", "  ")
	}
}

// ExportChain reads the ledger, filters by timestamp range, and outputs JSON or CSV.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func ExportChain(path, format, since, until string) ([]byte, error) {
	return defaultEngine.ExportChain(path, format, since, until)
}
