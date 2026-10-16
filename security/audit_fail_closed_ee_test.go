//go:build ee

package security

import (
	"net/http"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"
)

func TestAdminHTTPReadFailsClosedWhenAuditFails(t *testing.T) {
	session := &sys.Session{ID: "admin-audit-fail", User: "alice"}
	registerTestSession(t, session)
	eng, chain, _ := chainEngine(t)
	breakChain(t, eng, chain)
	rec := adminDo(t, NewAdminHTTPHandler(eng, "secret"), http.MethodGet, "/v1/sessions", "", "secret")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("read with broken audit = %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "admin-audit-fail") {
		t.Fatalf("unaudited response disclosed session data: %s", rec.Body.String())
	}
}

func TestAdminHTTPUnbanFailsClosedWhenAuditFails(t *testing.T) {
	eng, chain, _ := chainEngine(t)
	breakChain(t, eng, chain)
	h := NewAdminHTTPHandlerWithKeys(eng, "", []AdminKey{{Name: "bob", Key: testAdminKey("bob")}})
	// guard is inactive here, so reaching guard.Unban would answer 500.
	rec := adminDo(t, h, http.MethodPost, "/v1/guard/unban", `{"addr":"192.0.2.1"}`, testAdminKey("bob"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unban with broken audit = %d %s", rec.Code, rec.Body.String())
	}
}
