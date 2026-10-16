package security

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/afterdarksys/adssh/internal/guard"
	"github.com/afterdarksys/adssh/internal/sys"
)

// Threats: the admin API decides four-eyes requests, so the server must know
// who is calling. Each approver holds a named key from ADSSH_ADMIN_KEYS; the
// matching key's name is the authenticated principal and the only approver
// identity a decision can carry. A body that names an approver is refused.
// The legacy single key (ADSSH_ADMIN_API_KEY) is shared and anonymous, so it
// can read (lists, explain, evidence) and can never approve, deny, or unban.
// Every key is compared constant-time against every configured key; an empty
// key authenticates no one. Keys are never logged, only a SHA-256 fingerprint.
// The keys file must be a regular 0600 file owned by this user, opened without
// following a symlink. This does not rotate keys, rate-limit guesses, or
// protect a key that leaks from the holder's machine. /healthz is
// unauthenticated. The listener is loopback or a Unix socket (see adminListen).

// AdminKey is one named admin API key.
type AdminKey struct {
	Name string
	Key  string
}

const (
	adminKeysFileMax  = 64 << 10
	adminKeyMinBytes  = 32
	adminLegacyName   = "legacy"
	adminNoPrincipal  = "none"
	adminKeyFPDisplay = 12
)

var adminKeyNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// LoadAdminKeysFile reads name=key lines. Blank lines and lines starting with
// # are skipped. Names match [A-Za-z0-9_.-]{1,64}; keys are at least 32 bytes
// with no whitespace. A duplicate name or key, a group or world readable
// file, a file owned by another user, a symlink, or an empty file is refused.
func LoadAdminKeysFile(path string) ([]AdminKey, error) {
	if path == "" {
		return nil, fmt.Errorf("admin keys: path is empty")
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("admin keys: open directory: %w", err)
	}
	defer dir.Close()
	f, err := openAt(dir, filepath.Base(path), syscall.O_RDONLY)
	if err != nil {
		return nil, fmt.Errorf("admin keys: open %s: %w", filepath.Base(path), err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("admin keys: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("admin keys: not a regular file")
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("admin keys: file is group or world accessible (want 0600)")
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("admin keys: file is owned by another user")
	}
	if st.Size() > adminKeysFileMax {
		return nil, fmt.Errorf("admin keys: file is too large")
	}
	body, err := io.ReadAll(io.LimitReader(f, adminKeysFileMax+1))
	if err != nil {
		return nil, fmt.Errorf("admin keys: %w", err)
	}
	defer zeroBytes(body)
	if len(body) > adminKeysFileMax {
		return nil, fmt.Errorf("admin keys: file is too large")
	}
	return parseAdminKeys(string(body))
}

func parseAdminKeys(text string) ([]AdminKey, error) {
	var keys []AdminKey
	names := map[string]bool{}
	seen := map[[32]byte]bool{}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, key, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("admin keys: line %d: want name=key", i+1)
		}
		name = strings.TrimSpace(name)
		key = strings.TrimSpace(key)
		if !adminKeyNamePattern.MatchString(name) || name == adminLegacyName || name == adminNoPrincipal {
			return nil, fmt.Errorf("admin keys: line %d: invalid name", i+1)
		}
		if len(key) < adminKeyMinBytes || strings.ContainsAny(key, " \t\r") {
			return nil, fmt.Errorf("admin keys: line %d: key for %s must be at least %d bytes with no whitespace", i+1, name, adminKeyMinBytes)
		}
		if names[name] {
			return nil, fmt.Errorf("admin keys: line %d: duplicate name %s", i+1, name)
		}
		sum := sha256.Sum256([]byte(key))
		if seen[sum] {
			return nil, fmt.Errorf("admin keys: line %d: key for %s duplicates another key", i+1, name)
		}
		names[name] = true
		seen[sum] = true
		keys = append(keys, AdminKey{Name: name, Key: key})
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("admin keys: no keys")
	}
	return keys, nil
}

type adminPrincipal struct {
	Name  string
	Named bool
}

type adminPrincipalKey struct{}

func adminPrincipalFromContext(ctx context.Context) (adminPrincipal, bool) {
	p, ok := ctx.Value(adminPrincipalKey{}).(adminPrincipal)
	return p, ok
}

type adminHTTPHandler struct {
	engine    *Engine
	legacyKey string
	keys      []AdminKey
}

// NewAdminHTTPHandler serves the admin API with only the legacy shared key,
// which can read and cannot decide or unban.
func NewAdminHTTPHandler(engine *Engine, apiKey string) http.Handler {
	return NewAdminHTTPHandlerWithKeys(engine, apiKey, nil)
}

// NewAdminHTTPHandlerWithKeys serves the admin API with named per-approver
// keys and an optional read-only legacy key.
func NewAdminHTTPHandlerWithKeys(engine *Engine, legacyKey string, keys []AdminKey) http.Handler {
	if engine == nil {
		engine = DefaultEngine()
	}
	return &adminHTTPHandler{engine: engine, legacyKey: legacyKey, keys: append([]AdminKey(nil), keys...)}
}

func (h *adminHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	principal, ok := h.authenticate(r)
	name := adminNoPrincipal
	if ok {
		name = principal.Name
		h.serveAuthorized(rec, r.WithContext(context.WithValue(r.Context(), adminPrincipalKey{}, principal)))
	} else {
		writeAdminJSON(rec, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
	}
	h.engine.LogEvent(fmt.Sprintf("ADMIN_HTTP method=%s path=%s status=%d key_fp=%s principal=%s",
		r.Method, r.URL.Path, rec.status, presentedKeyFingerprint(r), name))
}

func (h *adminHTTPHandler) serveAuthorized(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/sessions":
		writeAdminJSON(w, http.StatusOK, sys.ListSessionInfo())
	case r.Method == http.MethodGet && r.URL.Path == "/v1/gateways":
		writeAdminJSON(w, http.StatusOK, adminGatewaySnapshot())
	case r.Method == http.MethodGet && r.URL.Path == "/v1/approvals":
		pending, err := h.engine.ListApprovalsPublic()
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, err)
			return
		}
		writeAdminJSON(w, http.StatusOK, pending)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/approvals/approve":
		if requireNamedAdmin(w, r) {
			h.handleApproval(w, r, true)
		}
	case r.Method == http.MethodPost && r.URL.Path == "/v1/approvals/deny":
		if requireNamedAdmin(w, r) {
			h.handleApproval(w, r, false)
		}
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
		if requireNamedAdmin(w, r) {
			h.handleGuardUnban(w, r)
		}
	default:
		writeAdminJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
	}
}

// requireNamedAdmin writes 403 unless a named key authenticated the request.
func requireNamedAdmin(w http.ResponseWriter, r *http.Request) bool {
	principal, ok := adminPrincipalFromContext(r.Context())
	if ok && principal.Named && principal.Name != "" {
		return true
	}
	writeAdminJSON(w, http.StatusForbidden, map[string]any{"error": "named admin key required"})
	return false
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

// authenticate checks every presented key against every configured key. A
// named key wins over the legacy key.
func (h *adminHTTPHandler) authenticate(r *http.Request) (adminPrincipal, bool) {
	presented := []string{r.Header.Get("X-ADSSH-API-Key")}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		presented = append(presented, strings.TrimPrefix(auth, "Bearer "))
	}
	named := -1
	legacy := false
	for _, key := range presented {
		for i, configured := range h.keys {
			if constantTimeEqual(key, configured.Key) && named < 0 {
				named = i
			}
		}
		if constantTimeEqual(key, h.legacyKey) {
			legacy = true
		}
	}
	if named >= 0 {
		return adminPrincipal{Name: h.keys[named].Name, Named: true}, true
	}
	if legacy {
		return adminPrincipal{Name: adminLegacyName}, true
	}
	return adminPrincipal{}, false
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
	principal, _ := adminPrincipalFromContext(r.Context())
	var body map[string]json.RawMessage
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(&body); err != nil {
		writeAdminError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
		return
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		writeAdminJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
		return
	}
	if _, ok := body["approver"]; ok {
		writeAdminJSON(w, http.StatusBadRequest, map[string]any{"error": "approver is taken from the admin key and must not be sent"})
		return
	}
	for field := range body {
		if field != "token" && field != "request_id" {
			writeAdminJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown field " + field})
			return
		}
	}
	var token, requestID string
	if raw, ok := body["token"]; ok && json.Unmarshal(raw, &token) != nil {
		writeAdminJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid token"})
		return
	}
	if raw, ok := body["request_id"]; ok && json.Unmarshal(raw, &requestID) != nil {
		writeAdminJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request_id"})
		return
	}
	if token != "" && requestID != "" {
		writeAdminJSON(w, http.StatusBadRequest, map[string]any{"error": "send request_id or token, not both"})
		return
	}
	if requestID != "" {
		token = requestID
	}
	if !validApprovalToken(token) {
		writeAdminJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid token"})
		return
	}
	if err := h.engine.DecideRequest(token, principal.Name, FourEyesSurfaceHTTP, approve); err != nil {
		switch {
		case errors.Is(err, errFourEyesDecisionsForbidden):
			writeAdminError(w, http.StatusForbidden, err)
		case errors.Is(err, errFourEyesAudit):
			writeAdminJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "audit_unavailable"})
		default:
			writeAdminError(w, http.StatusBadRequest, err)
		}
		return
	}
	action := "denied"
	if approve {
		action = "approved"
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true, "action": action, "approver": principal.Name})
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

func formatAdminHTTPStart(listen string, legacyKey string, keys []AdminKey) string {
	if legacyKey == "" && len(keys) == 0 {
		return fmt.Sprintf("admin: http listening on %s auth=refused-empty-key", listen)
	}
	legacy := "off"
	if legacyKey != "" {
		legacy = "read-only"
	}
	names := make([]string, 0, len(keys))
	for _, key := range keys {
		names = append(names, key.Name)
	}
	return fmt.Sprintf("admin: http listening on %s auth=token named=%s legacy=%s",
		listen, emptyDash(strings.Join(names, ",")), legacy)
}

// adminKeyFingerprints lists name:fingerprint-prefix pairs for the audit log.
func adminKeyFingerprints(keys []AdminKey) string {
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key.Name+":"+fingerprintSecret(key.Key)[:adminKeyFPDisplay])
	}
	return strings.Join(parts, ",")
}

func adminHTTPServerTimeouts(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}
