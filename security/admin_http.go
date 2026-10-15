package security

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/afterdarksys/adssh/internal/guard"
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
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	h.serveAuthorized(rec, r)
	h.engine.LogEvent(fmt.Sprintf("ADMIN_HTTP method=%s path=%s status=%d key_fp=%s",
		r.Method, r.URL.Path, rec.status, presentedKeyFingerprint(r)))
}

func (h *adminHTTPHandler) serveAuthorized(w http.ResponseWriter, r *http.Request) {
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
		pending, err := h.engine.ListPending()
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, err)
			return
		}
		writeAdminJSON(w, http.StatusOK, pending)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/approvals/approve":
		h.handleApproval(w, r, true)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/approvals/deny":
		h.handleApproval(w, r, false)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/explain":
		h.handleExplain(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/evidence":
		h.handleEvidence(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/recordings":
		items, err := h.engine.ListRecordings()
		writeAdminList(w, items, err)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/elevations":
		items, err := h.engine.ListElevations()
		writeAdminList(w, items, err)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/leases":
		items, err := h.engine.ListLeases()
		writeAdminList(w, items, err)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/guard":
		writeAdminJSON(w, http.StatusOK, guard.Status())
	case r.Method == http.MethodPost && r.URL.Path == "/v1/guard/unban":
		h.handleGuardUnban(w, r)
	default:
		writeAdminJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.wrote {
		return
	}
	s.wrote = true
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wrote {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(b)
}

func presentedKeyFingerprint(r *http.Request) string {
	key := r.Header.Get("X-ADSSH-API-Key")
	if key == "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			key = strings.TrimPrefix(auth, "Bearer ")
		}
	}
	if key == "" {
		return "absent"
	}
	return fingerprintSecret(key)
}

func writeAdminList(w http.ResponseWriter, value any, err error) {
	if err != nil {
		if errors.Is(err, errChainUnavailable) {
			writeAdminJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "chain_unavailable"})
			return
		}
		writeAdminJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeAdminJSON(w, http.StatusOK, value)
}

// Threats: an empty admin key must not authenticate anyone, and a raw
// compare must not leak the key through length. This does not store, rotate,
// or scope the key. /healthz stays unauthenticated.
func (h *adminHTTPHandler) authorized(r *http.Request) bool {
	if h.apiKey == "" {
		return false
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
	ah := sha256.Sum256([]byte(a))
	bh := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ah[:], bh[:]) == 1
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

func (h *adminHTTPHandler) handleApproval(w http.ResponseWriter, r *http.Request, approve bool) {
	var req struct {
		Token    string `json:"token"`
		Approver string `json:"approver"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
		return
	}
	if !validApprovalToken(req.Token) {
		writeAdminJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid token"})
		return
	}
	if req.Approver == "" {
		writeAdminJSON(w, http.StatusBadRequest, map[string]any{"error": "approver is required"})
		return
	}
	if approve {
		if err := h.engine.ApproveRequestAs(req.Token, req.Approver); err != nil {
			writeAdminError(w, http.StatusBadRequest, err)
			return
		}
		writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true, "action": "approved"})
		return
	}
	if err := h.engine.DenyRequestAs(req.Token, req.Approver); err != nil {
		writeAdminError(w, http.StatusBadRequest, err)
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true, "action": "denied"})
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

func (h *adminHTTPHandler) handleGuardUnban(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Addr string `json:"addr"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeAdminJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
		return
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		writeAdminJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
		return
	}
	key, err := guard.Unban(req.Addr)
	if err == nil {
		writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true, "addr": key})
		return
	}
	switch {
	case errors.Is(err, guard.ErrBadPeer):
		writeAdminJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_peer"})
	case errors.Is(err, guard.ErrNotBanned):
		writeAdminJSON(w, http.StatusNotFound, map[string]any{"error": "not_banned"})
	case errors.Is(err, guard.ErrInactive):
		writeAdminJSON(w, http.StatusInternalServerError, map[string]any{"error": "guard is not active"})
	default:
		writeAdminJSON(w, http.StatusInternalServerError, map[string]any{"error": "guard_unavailable"})
	}
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
	auth := "refused-empty-key"
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
