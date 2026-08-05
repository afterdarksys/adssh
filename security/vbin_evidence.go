package security

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mvdan.cc/sh/v3/interp"
)

type EvidenceFilter struct {
	SessionID string `json:"session_id,omitempty"`
	ChangeID  string `json:"change_id,omitempty"`
	Since     string `json:"since,omitempty"`
	Until     string `json:"until,omitempty"`
}

type EvidenceBundle struct {
	Version      int            `json:"version"`
	GeneratedAt  string         `json:"generated_at"`
	Verified     bool           `json:"verified"`
	Ledger       string         `json:"ledger"`
	ChainHead    string         `json:"chain_head,omitempty"`
	DigestSHA256 string         `json:"digest_sha256"`
	Filter       EvidenceFilter `json:"filter"`
	Entries      []ChainEntry   `json:"entries"`
	Recordings   []RecordingRef `json:"recordings,omitempty"`
	GatewayLog   *GatewayLogRef `json:"gateway_log,omitempty"`
}

type RecordingRef struct {
	SessionID    string `json:"session_id"`
	Path         string `json:"path"`
	SizeBytes    int64  `json:"size_bytes"`
	EventCount   int    `json:"event_count"`
	DigestSHA256 string `json:"digest_sha256"`
}

// BuildEvidence verifies the entire configured HMAC chain before returning a
// filtered bundle. Filtering never weakens verification: the full ledger is
// checked first and every returned entry retains its original chain hashes.
func (e *Engine) BuildEvidence(filter EvidenceFilter) (EvidenceBundle, error) {
	e.chainMu.Lock()
	ledger := e.chainPath
	e.chainMu.Unlock()
	if ledger == "" {
		return EvidenceBundle{}, fmt.Errorf("evidence: audit chain is not initialized")
	}
	verified, badSeq, err := e.VerifyChain(ledger)
	if err != nil {
		return EvidenceBundle{}, fmt.Errorf("evidence: chain verification failed: %w", err)
	}
	if !verified {
		return EvidenceBundle{}, fmt.Errorf("evidence: chain verification failed at sequence %d", badSeq)
	}
	since, err := parseEvidenceTime(filter.Since, false)
	if err != nil {
		return EvidenceBundle{}, fmt.Errorf("evidence: invalid --since: %w", err)
	}
	until, err := parseEvidenceTime(filter.Until, true)
	if err != nil {
		return EvidenceBundle{}, fmt.Errorf("evidence: invalid --until: %w", err)
	}

	file, err := os.Open(ledger)
	if err != nil {
		return EvidenceBundle{}, fmt.Errorf("evidence: open ledger: %w", err)
	}
	defer file.Close()
	entries := make([]ChainEntry, 0)
	chainHead := ""
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 2<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry ChainEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return EvidenceBundle{}, fmt.Errorf("evidence: parse verified ledger: %w", err)
		}
		chainHead = entry.Hash
		if filter.SessionID != "" && entry.SessionID != filter.SessionID {
			continue
		}
		if filter.ChangeID != "" && entry.ChangeID != filter.ChangeID {
			continue
		}
		timestamp, err := time.Parse(time.RFC3339Nano, entry.Timestamp)
		if err != nil {
			return EvidenceBundle{}, fmt.Errorf("evidence: entry %d has invalid timestamp: %w", entry.Seq, err)
		}
		if !since.IsZero() && timestamp.Before(since) {
			continue
		}
		if !until.IsZero() && timestamp.After(until) {
			continue
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return EvidenceBundle{}, fmt.Errorf("evidence: scan ledger: %w", err)
	}
	canonical, err := json.Marshal(entries)
	if err != nil {
		return EvidenceBundle{}, fmt.Errorf("evidence: encode digest input: %w", err)
	}
	recordings, err := buildRecordingRefs(filter, entries)
	if err != nil {
		return EvidenceBundle{}, err
	}
	var gatewayLog *GatewayLogRef
	if ref, ok, err := gatewayLogRef(); err != nil {
		return EvidenceBundle{}, err
	} else if ok {
		gatewayLog = &ref
	}
	digest := sha256.Sum256(canonical)
	return EvidenceBundle{
		Version:      1,
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		Verified:     true,
		Ledger:       ledger,
		ChainHead:    chainHead,
		DigestSHA256: hex.EncodeToString(digest[:]),
		Filter:       filter,
		Entries:      entries,
		Recordings:   recordings,
		GatewayLog:   gatewayLog,
	}, nil
}

func buildRecordingRefs(filter EvidenceFilter, entries []ChainEntry) ([]RecordingRef, error) {
	sessions := map[string]struct{}{}
	if filter.SessionID != "" {
		sessions[filter.SessionID] = struct{}{}
	}
	for _, entry := range entries {
		if entry.SessionID != "" {
			sessions[entry.SessionID] = struct{}{}
		}
	}
	refs := make([]RecordingRef, 0, len(sessions))
	for sessionID := range sessions {
		ref, ok, err := recordingRef(sessionID)
		if err != nil {
			return nil, err
		}
		if ok {
			refs = append(refs, ref)
		}
	}
	return refs, nil
}

func recordingRef(sessionID string) (RecordingRef, bool, error) {
	dir := os.Getenv("ADSSH_RECORD_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return RecordingRef{}, false, nil
		}
		dir = filepath.Join(home, ".adssh", "recordings")
	}
	path := filepath.Join(dir, sessionID+".jsonl")
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return RecordingRef{}, false, nil
		}
		return RecordingRef{}, false, fmt.Errorf("evidence: open recording %s: %w", path, err)
	}
	defer file.Close()
	hash := sha256.New()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 2<<20)
	events := 0
	var size int64
	for scanner.Scan() {
		line := scanner.Bytes()
		events++
		size += int64(len(line)) + 1
		_, _ = hash.Write(line)
		_, _ = hash.Write([]byte("\n"))
	}
	if err := scanner.Err(); err != nil {
		return RecordingRef{}, false, fmt.Errorf("evidence: scan recording %s: %w", path, err)
	}
	return RecordingRef{
		SessionID:    sessionID,
		Path:         path,
		SizeBytes:    size,
		EventCount:   events,
		DigestSHA256: hex.EncodeToString(hash.Sum(nil)),
	}, true, nil
}

func parseEvidenceTime(value string, endOfDay bool) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed, nil
	}
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		return time.Time{}, err
	}
	if endOfDay {
		parsed = parsed.Add(24*time.Hour - time.Nanosecond)
	}
	return parsed, nil
}

type evidenceBinary struct{}

func (evidenceBinary) Name() string { return "evidence" }
func (evidenceBinary) Description() string {
	return "Verify and export filtered HMAC-chain audit evidence bundles"
}
func (evidenceBinary) Usage() string {
	return "evidence [--session id] [--change id] [--since time] [--until time] [--out path]"
}

func (evidenceBinary) Run(ctx context.Context, args []string) error {
	filter := EvidenceFilter{}
	outputPath := ""
	for i := 1; i < len(args); i++ {
		var target *string
		switch args[i] {
		case "--session":
			target = &filter.SessionID
		case "--change":
			target = &filter.ChangeID
		case "--since":
			target = &filter.Since
		case "--until":
			target = &filter.Until
		case "--out":
			target = &outputPath
		default:
			return fmt.Errorf("evidence: unknown option %q", args[i])
		}
		if i+1 >= len(args) {
			return fmt.Errorf("evidence: %s requires a value", args[i])
		}
		i++
		*target = args[i]
	}
	return (evidenceBinary{}).write(ctx, engineFromContext(ctx), filter, outputPath)
}

func (evidenceBinary) write(ctx context.Context, engine *Engine, filter EvidenceFilter, outputPath string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	bundle, err := engine.BuildEvidence(filter)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("evidence: encode bundle: %w", err)
	}
	data = append(data, '\n')
	if outputPath == "" {
		hc := interp.HandlerCtx(ctx)
		_, err = hc.Stdout.Write(data)
		return err
	}
	return writePrivateAtomic(outputPath, data)
}

func writePrivateAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("evidence: create output directory: %w", err)
	}
	temp, err := os.CreateTemp(dir, ".adssh-evidence-*")
	if err != nil {
		return fmt.Errorf("evidence: create temporary bundle: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath) //nolint:errcheck
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return fmt.Errorf("evidence: secure temporary bundle: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("evidence: write bundle: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("evidence: sync bundle: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("evidence: close bundle: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("evidence: publish bundle: %w", err)
	}
	return nil
}
