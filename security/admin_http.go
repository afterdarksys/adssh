package security

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
)

type adminHTTPHandler struct {
	engine *Engine
	apiKey string
}

func NewAdminHTTPHandler(engine *Engine, apiKey string) http.Handler {
	if engine == nil {
		engine = DefaultEngine()
	}
	return &adminHTTPHandler{engine: engine, apiKey: apiKey}
}

func (h *adminHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if !h.authorized(r) {
		writeAdminJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/sessions":
		writeAdminJSON(w, http.StatusOK, sys.ListSessionInfo())
	case r.Method == http.MethodGet && r.URL.Path == "/v1/gateways":
		writeAdminJSON(w, http.StatusOK, adminGatewaySnapshot())
	case r.Method == http.MethodGet && r.URL.Path == "/v1/approvals":
		pending, err := ListPending()
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, err)
			return
		}
		writeAdminJSON(w, http.StatusOK, pending)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/explain":
		h.handleExplain(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/evidence":
		h.handleEvidence(w, r)
	default:
		writeAdminJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
	}
}

func (h *adminHTTPHandler) authorized(r *http.Request) bool {
	if h.apiKey == "" {
		return true
	}
	if constantTimeEqual(r.Header.Get("X-ADSSH-API-Key"), h.apiKey) {
		return true
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	return constantTimeEqual(strings.TrimPrefix(auth, "Bearer "), h.apiKey)
}

func constantTimeEqual(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (h *adminHTTPHandler) handleExplain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string   `json:"session_id"`
		Command   []string `json:"command"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
		return
	}
	if len(req.Command) == 0 {
		writeAdminJSON(w, http.StatusBadRequest, map[string]any{"error": "command is required"})
		return
	}
	explanation, err := h.engine.ExplainCommand(req.SessionID, req.Command)
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, err)
		return
	}
	writeAdminJSON(w, http.StatusOK, explanation)
}

func (h *adminHTTPHandler) handleEvidence(w http.ResponseWriter, r *http.Request) {
	var filter EvidenceFilter
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&filter); err != nil {
		writeAdminError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
		return
	}
	bundle, err := h.engine.BuildEvidence(filter)
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, err)
		return
	}
	writeAdminJSON(w, http.StatusOK, bundle)
}

func adminGatewaySnapshot() []map[string]any {
	gatewayMu.RLock()
	sessions := make([]*gatewaySession, 0, len(gatewaySessions))
	for _, session := range gatewaySessions {
		sessions = append(sessions, session)
	}
	gatewayMu.RUnlock()
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].ID < sessions[j].ID })

	out := make([]map[string]any, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, map[string]any{
			"id":         s.ID,
			"name":       s.Name,
			"listen":     s.Listen,
			"target":     s.Target,
			"user":       s.User,
			"started_at": s.Started,
		})
	}
	return out
}

func writeAdminJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeAdminError(w http.ResponseWriter, status int, err error) {
	writeAdminJSON(w, status, map[string]any{"error": err.Error()})
}

func formatAdminHTTPStart(listen string, apiKey string) string {
	auth := "disabled"
	if apiKey != "" {
		auth = "token"
	}
	return fmt.Sprintf("admin: http listening on %s auth=%s", listen, auth)
}

func adminHTTPServerTimeouts(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
}
