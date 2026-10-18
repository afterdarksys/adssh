package security

// Helpers shared by core code and the enterprise (*_ee.go) files. They lived
// in the admin files until the open-core split; the core build needs them.

import (
	"crypto/sha256"
	"crypto/subtle"
	"strings"

	"github.com/afterdarksys/adssh/internal/sys"
)

func constantTimeEqual(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ah := sha256.Sum256([]byte(a))
	bh := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ah[:], bh[:]) == 1
}

// controllerTag is " via=<key>" while an rw attach controls the session.
func controllerTag(sessionID string) string {
	if sessionID == "" {
		return ""
	}
	if s := sys.GetSession(sessionID); s != nil {
		if c := s.Controller(); c != "" {
			return " via=" + c
		}
	}
	return ""
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

func leasesFromEntries(entries []ChainEntry) []LeaseEvidence {
	order := make([]string, 0)
	byID := map[string]*LeaseEvidence{}
	for _, entry := range entries {
		if !isEngineEvent(entry) {
			continue
		}
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

// isEngineEvent is true for a ledger entry written by LogEvent. Typed shell
// input is logged as Type "cmd" with a Source, so it cannot pass.
func isEngineEvent(entry ChainEntry) bool {
	return entry.Type == "event" && entry.Source == ""
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
