package security

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type GatewayConnectionRecord struct {
	ID            string `json:"id"`
	GatewayID     string `json:"gateway_id"`
	Name          string `json:"name,omitempty"`
	User          string `json:"user,omitempty"`
	Listen        string `json:"listen"`
	Target        string `json:"target"`
	OpenedAt      string `json:"opened_at"`
	ClosedAt      string `json:"closed_at"`
	DurationMS    int64  `json:"duration_ms"`
	BytesToTarget int64  `json:"bytes_to_target"`
	BytesToClient int64  `json:"bytes_to_client"`
	CloseReason   string `json:"close_reason"`
}

type GatewayLogRef struct {
	Path         string `json:"path"`
	SizeBytes    int64  `json:"size_bytes"`
	EventCount   int    `json:"event_count"`
	DigestSHA256 string `json:"digest_sha256"`
}

var (
	gatewayEvidenceMu sync.Mutex
	gatewayConnSeqMu  sync.Mutex
	gatewayConnSeq    int64
)

func nextGatewayConnectionID() string {
	gatewayConnSeqMu.Lock()
	defer gatewayConnSeqMu.Unlock()
	gatewayConnSeq++
	return fmt.Sprintf("gwc-%d", gatewayConnSeq)
}

func gatewayEvidencePath() string {
	if path := os.Getenv("ADSSH_GATEWAY_LOG"); path != "" {
		return path
	}
	if dir := os.Getenv("ADSSH_RECORD_DIR"); dir != "" {
		return filepath.Join(dir, "gateway_connections.jsonl")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".adssh", "recordings", "gateway_connections.jsonl")
}

func appendGatewayConnectionRecord(record GatewayConnectionRecord) {
	path := gatewayEvidencePath()
	if path == "" {
		return
	}
	gatewayEvidenceMu.Lock()
	defer gatewayEvidenceMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer file.Close()
	data, err := json.Marshal(record)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintln(file, string(data))
}

func gatewayLogRef() (GatewayLogRef, bool, error) {
	path := gatewayEvidencePath()
	if path == "" {
		return GatewayLogRef{}, false, nil
	}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return GatewayLogRef{}, false, nil
		}
		return GatewayLogRef{}, false, fmt.Errorf("evidence: open gateway log %s: %w", path, err)
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
		return GatewayLogRef{}, false, fmt.Errorf("evidence: scan gateway log %s: %w", path, err)
	}
	return GatewayLogRef{
		Path:         path,
		SizeBytes:    size,
		EventCount:   events,
		DigestSHA256: hex.EncodeToString(hash.Sum(nil)),
	}, true, nil
}

type countingWriter struct {
	writer ioWriter
	count  *int64
}

type ioWriter interface {
	Write([]byte) (int, error)
}

func (w countingWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	atomic.AddInt64(w.count, int64(n))
	return n, err
}

func newGatewayConnectionRecord(session *gatewaySession) GatewayConnectionRecord {
	return GatewayConnectionRecord{
		ID:        nextGatewayConnectionID(),
		GatewayID: session.ID,
		Name:      session.Name,
		User:      session.User,
		Listen:    session.Listen,
		Target:    session.Target,
		OpenedAt:  time.Now().UTC().Format(time.RFC3339Nano),
	}
}
