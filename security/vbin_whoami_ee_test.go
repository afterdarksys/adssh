//go:build ee

package security

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"
)

func TestAdminHTTPWhoamiEndpoint(t *testing.T) {
	eng := whoamiEngine(t)
	session := &sys.Session{ID: "whoami-admin", User: "alice", Principals: []string{"ops"}}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	handler := NewAdminHTTPHandler(eng, "secret")

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/whoami", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer secret")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	rec := post(`{"session_id":"whoami-admin","caps":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var report WhoamiReport
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.User != "alice" || report.Caps == nil || len(report.Caps.Probes) == 0 {
		t.Fatalf("report = %#v", report)
	}
	if rec := post(`{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing session_id status = %d", rec.Code)
	}
	if rec := post(`{"session_id":"whoami-admin-nobody"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown session status = %d body=%s", rec.Code, rec.Body.String())
	}
}
