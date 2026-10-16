//go:build ee

package security

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/internal/guard"
)

func TestAdminGuardRoutes(t *testing.T) {
	guard.ResetForTest()
	t.Cleanup(guard.ResetForTest)
	dir := t.TempDir()
	if err := guard.Configure(guard.Options{
		ConfigPath: filepath.Join(dir, "guard.yaml"),
		StatePath:  filepath.Join(dir, "guard-state.json"),
	}); err != nil {
		t.Fatal(err)
	}
	eng, err := NewEngine(EngineConfig{
		AuditLogPath: filepath.Join(dir, "audit.log"),
		ChainPath:    filepath.Join(dir, "chain"),
		ChainKeyPath: filepath.Join(dir, "key"),
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAdminHTTPHandlerWithKeys(eng, "secret", []AdminKey{{Name: "ops", Key: testAdminKey("ops")}})

	wrong := httptest.NewRecorder()
	wrongReq := httptest.NewRequest(http.MethodGet, "/v1/guard", nil)
	wrongReq.Header.Set("Authorization", "Bearer nope")
	handler.ServeHTTP(wrong, wrongReq)
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key GET = %d", wrong.Code)
	}

	ok := httptest.NewRecorder()
	okReq := httptest.NewRequest(http.MethodGet, "/v1/guard", nil)
	okReq.Header.Set("Authorization", "Bearer secret")
	handler.ServeHTTP(ok, okReq)
	if ok.Code != http.StatusOK || !strings.Contains(ok.Body.String(), `"enabled"`) {
		t.Fatalf("GET = %d %s", ok.Code, ok.Body.String())
	}

	postWrong := httptest.NewRecorder()
	postWrongReq := httptest.NewRequest(http.MethodPost, "/v1/guard/unban", strings.NewReader(`{"addr":"203.0.113.10"}`))
	postWrongReq.Header.Set("Authorization", "Bearer nope")
	handler.ServeHTTP(postWrong, postWrongReq)
	if postWrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key POST = %d", postWrong.Code)
	}

	legacy := httptest.NewRecorder()
	legacyReq := httptest.NewRequest(http.MethodPost, "/v1/guard/unban", strings.NewReader(`{"addr":"203.0.113.10"}`))
	legacyReq.Header.Set("Authorization", "Bearer secret")
	handler.ServeHTTP(legacy, legacyReq)
	if legacy.Code != http.StatusForbidden {
		t.Fatalf("legacy key POST = %d", legacy.Code)
	}

	post := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/guard/unban", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+testAdminKey("ops"))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	for _, body := range []string{`{}`, `{"addr":"not-an-ip"}`, `{"addr":"203.0.113.10","extra":true}`, `{"addr":"203.0.113.10"}{"addr":"203.0.113.11"}`} {
		rec := post(body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %s = %d %s", body, rec.Code, rec.Body.String())
		}
	}
	missing := post(`{"addr":"203.0.113.10"}`)
	if missing.Code != http.StatusNotFound || strings.TrimSpace(missing.Body.String()) != `{"error":"not_banned"}` {
		t.Fatalf("unknown unban = %d %s", missing.Code, missing.Body.String())
	}
}
