package security

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
)

// Threats: list endpoints read the operator's recording directory and the
// HMAC ledger. They do not create a second store that could disagree with
// those files. A missing or unverified chain fails closed for elevations and
// leases. Recording names are basenames only. This does not hide an approval
// token from an authenticated admin-key holder on GET /v1/approvals.

var errChainUnavailable = errors.New("chain_unavailable")

var (
	elevateRequestPattern = regexp.MustCompile(`^ELEVATE_REQUEST: session=(\S+) user=(\S+) role=(\S+) ttl=(\S+) reason="([^"]*)" expires_at=(\S+)`)
	elevateDropPattern    = regexp.MustCompile(`^ELEVATE_DROP: session=(\S+) user=(\S+) role=(\S+) reason="([^"]*)"`)
)

// RecordingListItem is one JSONL recording file.
type RecordingListItem struct {
	SessionID string `json:"session_id"`
	Name      string `json:"name"`
	SizeBytes int64  `json:"size_bytes"`
}

// ElevationListItem is one elevation request, drop, or still-active grant.
type ElevationListItem struct {
	SessionID string `json:"session_id"`
	User      string `json:"user"`
	Role      string `json:"role"`
	TTL       string `json:"ttl,omitempty"`
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Action    string `json:"action"`
	Active    bool   `json:"active,omitempty"`
}

// LeaseEvidence is one lease request and whether a later grant used the same id.
// Command text is not stored.
type LeaseEvidence struct {
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	SourceName  string `json:"source"`
	Destination string `json:"destination"`
	TTL         string `json:"ttl"`
	Delivery    string `json:"delivery"`
	Granted     bool   `json:"granted"`
}

// ApprovalPublic is a pending approval without the secret token.
type ApprovalPublic struct {
	RequestID   string       `json:"request_id,omitempty"`
	Fingerprint string       `json:"fingerprint,omitempty"`
	Command     string       `json:"command"`
	Requester   string       `json:"requester"`
	Hostname    string       `json:"hostname"`
	Timestamp   string       `json:"timestamp"`
	Rule        FourEyesRule `json:"rule"`
}

// AdminHTTPPaths is the route table served by the local admin handler.
func AdminHTTPPaths() []string {
	return []string{
		"/healthz",
		"/v1/sessions",
		"/v1/gateways",
		"/v1/approvals",
		"/v1/approvals/approve",
		"/v1/approvals/deny",
		"/v1/explain",
		"/v1/evidence",
		"/v1/recordings",
		"/v1/elevations",
		"/v1/leases",
	}
}

// ListRecordings returns regular *.jsonl files in the recording directory.
// A missing directory is an empty list.
func (e *Engine) ListRecordings() ([]RecordingListItem, error) {
	dir, err := recordingListDir()
	if err != nil || dir == "" {
		return []RecordingListItem{}, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []RecordingListItem{}, nil
		}
		return nil, err
	}
	out := make([]RecordingListItem, 0)
	for _, ent := range entries {
		name := ent.Name()
		if !strings.HasSuffix(name, ".jsonl") || !ent.Type().IsRegular() {
			continue
		}
		if filepath.Base(name) != name || strings.Contains(name, "..") || strings.ContainsAny(name, `/\`) {
			continue
		}
		info, err := ent.Info()
		if err != nil {
			continue
		}
		sessionID := strings.TrimSuffix(name, ".jsonl")
		if sessionID == "" || sessionID == "." || sessionID == ".." {
			continue
		}
		out = append(out, RecordingListItem{
			SessionID: sessionID,
			Name:      name,
			SizeBytes: info.Size(),
		})
	}
	return out, nil
}

func recordingListDir() (string, error) {
	if dir := os.Getenv("ADSSH_RECORD_DIR"); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", err
	}
	return filepath.Join(home, ".adssh", "recordings"), nil
}

// ListElevations reads elevation history from a verified chain and, only when
// that chain file exists, adds in-memory elevations that are still active.
func (e *Engine) ListElevations() ([]ElevationListItem, error) {
	entries, exists, err := e.readVerifiedChain()
	if err != nil {
		return nil, err
	}
	if !exists {
		return []ElevationListItem{}, nil
	}
	items := elevationsFromEntries(entries)
	items = append(items, activeElevations()...)
	if items == nil {
		return []ElevationListItem{}, nil
	}
	return items, nil
}

// ListLeases reads lease requests from a verified chain.
func (e *Engine) ListLeases() ([]LeaseEvidence, error) {
	entries, exists, err := e.readVerifiedChain()
	if err != nil {
		return nil, err
	}
	if !exists {
		return []LeaseEvidence{}, nil
	}
	leases := leasesFromEntries(entries)
	if leases == nil {
		return []LeaseEvidence{}, nil
	}
	return leases, nil
}

// ListApprovalsPublic lists pending approvals without the secret token.
// A new request exposes its public request id. A legacy file exposes a
// fingerprint of the stored token.
func (e *Engine) ListApprovalsPublic() ([]ApprovalPublic, error) {
	pending, err := e.ListPending()
	if err != nil {
		return nil, err
	}
	out := make([]ApprovalPublic, 0, len(pending))
	for _, item := range pending {
		public := ApprovalPublic{
			Command:   item.Command,
			Requester: item.Requester,
			Hostname:  item.Hostname,
			Timestamp: item.Timestamp,
			Rule:      item.Rule,
		}
		if item.RequestID != "" {
			public.RequestID = item.RequestID
		} else if item.Token != "" {
			public.Fingerprint = fingerprintSecret(item.Token)
		}
		out = append(out, public)
	}
	return out, nil
}

// readVerifiedChain copies the ledger path under chainMu and verifies it
// without holding that lock. VerifyChain locks chainMu itself.
func (e *Engine) readVerifiedChain() ([]ChainEntry, bool, error) {
	e.chainMu.Lock()
	path := e.chainPath
	e.chainMu.Unlock()
	if path == "" {
		return nil, false, errChainUnavailable
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, true, fmt.Errorf("audit chain is not a regular file")
	}
	ok, badSeq, err := e.VerifyChain(path)
	if err != nil {
		return nil, true, err
	}
	if !ok {
		return nil, true, fmt.Errorf("audit chain verification failed at sequence %d", badSeq)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, true, err
	}
	defer file.Close()
	entries := make([]ChainEntry, 0)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 2<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry ChainEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, true, fmt.Errorf("parse audit chain: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, true, err
	}
	return entries, true, nil
}

func elevationsFromEntries(entries []ChainEntry) []ElevationListItem {
	items := make([]ElevationListItem, 0)
	for _, entry := range entries {
		if matches := elevateRequestPattern.FindStringSubmatch(entry.Command); matches != nil {
			items = append(items, ElevationListItem{
				SessionID: matches[1],
				User:      matches[2],
				Role:      matches[3],
				TTL:       matches[4],
				Reason:    matches[5],
				ExpiresAt: matches[6],
				Action:    "request",
			})
			continue
		}
		if matches := elevateDropPattern.FindStringSubmatch(entry.Command); matches != nil {
			items = append(items, ElevationListItem{
				SessionID: matches[1],
				User:      matches[2],
				Role:      matches[3],
				Reason:    matches[4],
				Action:    "drop",
			})
		}
	}
	return items
}

func activeElevations() []ElevationListItem {
	infos := sys.ListSessionInfo()
	items := make([]ElevationListItem, 0)
	for _, info := range infos {
		if info.Elevation == nil {
			continue
		}
		items = append(items, ElevationListItem{
			SessionID: info.ID,
			User:      info.User,
			Role:      info.Elevation.Role,
			Reason:    info.Elevation.Reason,
			ExpiresAt: info.Elevation.ExpiresAt.UTC().Format(time.RFC3339),
			Action:    "active",
			Active:    true,
		})
	}
	return items
}

func leasesFromEntries(entries []ChainEntry) []LeaseEvidence {
	order := make([]string, 0)
	byID := map[string]*LeaseEvidence{}
	for _, entry := range entries {
		cmd := entry.Command
		switch {
		case strings.HasPrefix(cmd, "LEASE_REQUEST "):
			fields := parseLeaseFields(cmd)
			id := fields["id"]
			if id == "" {
				continue
			}
			if _, ok := byID[id]; ok {
				continue
			}
			delivery := fields["delivery"]
			if delivery == "" {
				delivery = "env"
			}
			order = append(order, id)
			byID[id] = &LeaseEvidence{
				ID:          id,
				Provider:    fields["source_type"],
				SourceName:  fields["source"],
				Destination: fields["as"],
				TTL:         fields["ttl"],
				Delivery:    delivery,
				Granted:     false,
			}
		case strings.HasPrefix(cmd, "LEASE_GRANT "):
			id := parseLeaseFields(cmd)["id"]
			if item, ok := byID[id]; ok {
				item.Granted = true
			}
		}
	}
	if len(order) == 0 {
		return nil
	}
	out := make([]LeaseEvidence, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out
}

func parseLeaseFields(cmd string) map[string]string {
	if idx := strings.Index(cmd, " command="); idx >= 0 {
		cmd = cmd[:idx]
	}
	out := map[string]string{}
	for _, part := range strings.Fields(cmd) {
		key, value, ok := strings.Cut(part, "=")
		if !ok || key == "" {
			continue
		}
		if _, exists := out[key]; exists {
			continue
		}
		out[key] = value
	}
	return out
}
