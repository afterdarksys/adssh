package security

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// ChainEntry is one line in the audit ledger.
// It is serialized as a single JSON object per line.
type ChainEntry struct {
	Seq       int64  `json:"seq"`
	Timestamp string `json:"ts"` // RFC3339Nano UTC
	SessionID string `json:"session"`
	User      string `json:"user"`
	Hostname  string `json:"host"`
	Type      string `json:"type"` // "cmd", "policy", "event", "4eyes", "cm"
	Command   string `json:"cmd,omitempty"`
	Source    string `json:"source,omitempty"`
	Allowed   *bool  `json:"allowed,omitempty"`
	Reason    string `json:"reason,omitempty"`
	ChangeID  string `json:"change_id,omitempty"` // CM ticket if set
	PrevHash  string `json:"prev_hash"`
	Hash      string `json:"hash"`
}

// chainEntryForHash is ChainEntry without the Hash field, used for HMAC computation.
type chainEntryForHash struct {
	Seq       int64  `json:"seq"`
	Timestamp string `json:"ts"`
	SessionID string `json:"session"`
	User      string `json:"user"`
	Hostname  string `json:"host"`
	Type      string `json:"type"`
	Command   string `json:"cmd,omitempty"`
	Source    string `json:"source,omitempty"`
	Allowed   *bool  `json:"allowed,omitempty"`
	Reason    string `json:"reason,omitempty"`
	ChangeID  string `json:"change_id,omitempty"`
	PrevHash  string `json:"prev_hash"`
}

// InitChain loads or creates the HMAC key, then records the ledger path.
// The path stays unset when the key cannot be loaded, so a failed init does
// not leave a half-configured chain that would later fail open.
func (e *Engine) InitChain(ledgerPath, keyPath, sessionID string) error {
	key, err := loadOrCreateChainKey(keyPath)
	if err != nil {
		return fmt.Errorf("audit chain: failed to load/create key: %w", err)
	}
	e.chainMu.Lock()
	defer e.chainMu.Unlock()
	e.chainPath = ledgerPath
	e.chainSession = sessionID
	e.chainKey = key
	return nil
}

// InitChain sets the ledger path, loads or creates the HMAC key, and sets the session ID.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func InitChain(ledgerPath, keyPath, sessionID string) error {
	return defaultEngine.InitChain(ledgerPath, keyPath, sessionID)
}

// chainKeyError is the refusal for a key file that exists but cannot be used.
type chainKeyError struct {
	path  string
	cause error
}

func (e *chainKeyError) Error() string {
	msg := fmt.Sprintf("audit chain key %s is unreadable or the wrong size; restore it from backup or move it aside to start a new ledger", e.path)
	if e.cause != nil {
		return msg + ": " + e.cause.Error()
	}
	return msg
}

func (e *chainKeyError) Unwrap() error { return e.cause }

// asChainKeyError keeps a chainKeyError as is and wraps any other error.
func asChainKeyError(path string, err error) error {
	var keyErr *chainKeyError
	if errors.As(err, &keyErr) {
		return err
	}
	return &chainKeyError{path: path, cause: err}
}

// readChainKey reads an existing key. A file that cannot be read or is not
// exactly 32 bytes is an error, never a reason to make a new key.
func readChainKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) != 32 {
		return nil, &chainKeyError{path: path}
	}
	return data, nil
}

// loadOrCreateChainKey reads the HMAC key from path, or creates it when no
// file exists there.
//
// Threats: adssh and adssh-mcp share the default key path, so two processes
// can start together on a fresh host. The key is written in full to a 0600
// temp file in the same directory, synced, and then hard-linked to path; the
// link fails if path already exists, so the first creator wins and every
// other creator reads the winner's key instead of overwriting it. A reader
// never sees a partial key. An existing key file is never replaced: one that
// cannot be read or is not exactly 32 bytes is an error, because a new key
// would orphan the ledger. Not covered: filesystems without hard links (the
// create fails closed) and a key file removed while processes run.
func loadOrCreateChainKey(path string) ([]byte, error) {
	key, err := readChainKey(path)
	if err == nil {
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, asChainKeyError(path, err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".chainkey-*")
	if err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("write key: %w", err)
	}
	if _, err := tmp.Write(key); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("write key: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("write key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}
	if err := os.Link(tmpName, path); err != nil {
		if os.IsExist(err) {
			// Another process created the key first; use it.
			existing, rerr := readChainKey(path)
			if rerr != nil {
				return nil, asChainKeyError(path, rerr)
			}
			return existing, nil
		}
		return nil, fmt.Errorf("write key: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		serr := d.Sync()
		cerr := d.Close()
		if serr != nil {
			return nil, fmt.Errorf("sync key dir: %w", serr)
		}
		if cerr != nil {
			return nil, fmt.Errorf("sync key dir: %w", cerr)
		}
	} else {
		return nil, fmt.Errorf("sync key dir: %w", err)
	}
	return key, nil
}

// chainScanMax is the largest ledger line the scanner will accept. A longer
// line is an error, not a missing ledger.
const chainScanMax = 1 << 20

func newChainScanner(r interface{ Read([]byte) (int, error) }) *bufio.Scanner {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), chainScanMax)
	return scanner
}

// computeHash computes the HMAC-SHA256 of prev + "\n" + JSON(entry without Hash).
func computeHash(key []byte, prev string, entry ChainEntry) (string, error) {
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
	entryJSON, err := json.Marshal(withoutHash)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(prev))
	mac.Write([]byte("\n"))
	mac.Write(entryJSON)
	return hex.EncodeToString(mac.Sum(nil)), nil
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

// chainLockTimeout bounds how long AppendChain waits for another process
// that holds the ledger lock. A stuck holder makes the append fail closed
// instead of hanging the gate.
const chainLockTimeout = 5 * time.Second

// chainLockPoll is the retry interval while the ledger lock is held elsewhere.
const chainLockPoll = 10 * time.Millisecond

// lockChainFile takes an exclusive advisory lock on f, retrying a
// non-blocking flock until chainLockTimeout passes. The lock belongs to the
// open file description and is released when f is closed.
func lockChainFile(f *os.File) error {
	deadline := time.Now().Add(chainLockTimeout)
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if err == unix.EINTR {
			continue
		}
		if err != unix.EWOULDBLOCK {
			return fmt.Errorf("audit chain: lock ledger: %w", err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("audit chain: ledger lock held by another process for more than %v", chainLockTimeout)
		}
		time.Sleep(chainLockPoll)
	}
}

// readLastChainLine reads the last non-empty line of the ledger by reading
// backward from the end, so the cost does not grow with the ledger. It checks
// the tail entry's HMAC against key. A missing or empty file starts at seq 0.
// A file that exists but cannot be read, a last line that does not parse, a
// line longer than chainScanMax, or a tail whose HMAC does not verify is an
// error. Callers must not treat that error as a new genesis entry.
func readLastChainLine(path string, key []byte) (prevHash string, nextSeq int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", 0, nil
		}
		return "", 0, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	end := info.Size()

	// Collect bytes from the end until the buffer holds one whole non-empty
	// line: a newline before some non-whitespace, or the start of the file.
	const block = 64 * 1024
	var buf []byte
	pos := end
	for {
		trimmed := strings.TrimRight(string(buf), " \t\r\n")
		if trimmed != "" {
			if i := strings.LastIndexByte(trimmed, '\n'); i >= 0 || pos == 0 {
				lastLine := strings.TrimSpace(trimmed[i+1:])
				if len(lastLine) > chainScanMax {
					return "", 0, fmt.Errorf("%w: tail line exceeds %d bytes", errChainTailUnverified, chainScanMax)
				}
				return parseChainTail(lastLine, key)
			}
		} else if pos == 0 {
			return "", 0, nil
		}
		if int64(len(buf)) > chainScanMax+block {
			return "", 0, fmt.Errorf("%w: tail line exceeds %d bytes", errChainTailUnverified, chainScanMax)
		}
		n := int64(block)
		if pos < n {
			n = pos
		}
		pos -= n
		chunk := make([]byte, n)
		if _, err := f.ReadAt(chunk, pos); err != nil {
			return "", 0, err
		}
		buf = append(chunk, buf...)
	}
}

// errChainTailUnverified marks a ledger tail that does not parse or verify.
var errChainTailUnverified = errors.New("audit chain")

// parseChainTail parses the tail entry and checks its HMAC over its own
// prev_hash. A tail that does not verify was written without the key or
// changed afterward, so the next entry must not chain onto it.
func parseChainTail(line string, key []byte) (prevHash string, nextSeq int64, err error) {
	var entry ChainEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return "", 0, fmt.Errorf("%w: corrupt tail: %v", errChainTailUnverified, err)
	}
	if entry.Hash == "" {
		return "", 0, fmt.Errorf("%w: corrupt tail: empty hash", errChainTailUnverified)
	}
	want, err := computeHash(key, entry.PrevHash, entry)
	if err != nil {
		return "", 0, err
	}
	if !hmac.Equal([]byte(want), []byte(entry.Hash)) {
		return "", 0, fmt.Errorf("%w: tail entry seq %d fails HMAC check", errChainTailUnverified, entry.Seq)
	}
	return entry.Hash, entry.Seq + 1, nil
}

// AppendChain appends a new entry to the HMAC chain ledger and Syncs it.
// It is a no-op if InitChain has not been called.
//
// Threats: one ledger may be shared by cooperating processes on one host that
// hold the same key (adssh and adssh-mcp default to the same path, and two
// REPL windows do too). Each append takes an exclusive flock on the ledger,
// reads the tail from disk under that lock, and writes and Syncs before the
// lock is released, so processes cannot fork the chain into duplicate seqs.
// The in-memory tail is a record of this engine's last write, never the
// source of the next seq. A tail whose HMAC does not verify, or a partial
// tail line, fails the append closed. A lock held longer than
// chainLockTimeout fails the append closed rather than hanging the gate.
// Not covered: sharing a ledger across hosts (flock over NFS or other network
// filesystems is not reliable), writers that ignore the lock, and truncation
// of the most recent entries, which VerifyChain cannot see.
func (e *Engine) AppendChain(entry ChainEntry) error {
	e.chainMu.Lock()
	defer e.chainMu.Unlock()

	if e.chainPath == "" || e.chainKey == nil {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(e.chainPath), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(e.chainPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	// Closing f releases the flock, after the write has been Synced.
	defer f.Close()
	if err := lockChainFile(f); err != nil {
		return err
	}

	prevHash, nextSeq, err := readLastChainLine(e.chainPath, e.chainKey)
	if err != nil {
		if errors.Is(err, errChainTailUnverified) {
			return fmt.Errorf("%w; the ledger tail does not verify; rotate the ledger (move %s aside) to continue — do not edit it", err, e.chainPath)
		}
		return err
	}

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
	hash, err := computeHash(e.chainKey, prevHash, entry)
	if err != nil {
		return err
	}
	entry.Hash = hash

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := syncFile(f); err != nil {
		return err
	}
	return nil
}

// AppendChain appends a new entry to the HMAC chain ledger.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func AppendChain(entry ChainEntry) error {
	return defaultEngine.AppendChain(entry)
}

// ChainEnabled reports whether this engine has a ledger path and a
// 32-byte HMAC key. Recovery refuses to start when it is false.
func (e *Engine) ChainEnabled() bool {
	if e == nil {
		return false
	}
	e.chainMu.Lock()
	defer e.chainMu.Unlock()
	return e.chainPath != "" && len(e.chainKey) == 32
}

// chainMaterial copies the ledger path and HMAC key. The caller zeros the
// copy after use. ok is false when the chain is not enabled.
func (e *Engine) chainMaterial() (path string, key []byte, ok bool) {
	if e == nil {
		return "", nil, false
	}
	e.chainMu.Lock()
	defer e.chainMu.Unlock()
	if e.chainPath == "" || len(e.chainKey) != 32 {
		return "", nil, false
	}
	key = make([]byte, len(e.chainKey))
	copy(key, e.chainKey)
	return e.chainPath, key, true
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
		return false, -1, fmt.Errorf("chain not initialized")
	}

	var prev string
	var lineNum int64

	scanner := newChainScanner(f)
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
		expected, hashErr := computeHash(key, prev, entry)
		if hashErr != nil {
			return false, entry.Seq, hashErr
		}
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
	scanner := newChainScanner(f)
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
