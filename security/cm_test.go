package security

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// CM env access isn't mutex'd, so none of these tests use t.Parallel().

func TestIsTicketValid(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	cases := []struct {
		name   string
		ticket *CMTicket
		want   bool
	}{
		{"nil ticket", nil, false},
		{"open state", &CMTicket{State: "open"}, false},
		{"approved no window", &CMTicket{State: "approved"}, true},
		{"approved future start window", &CMTicket{State: "approved", StartWindow: future}, false},
		{"approved past end window", &CMTicket{State: "approved", EndWindow: past}, false},
		{"approved inside window", &CMTicket{State: "approved", StartWindow: past, EndWindow: future}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsTicketValid(tc.ticket); got != tc.want {
				t.Errorf("IsTicketValid(%+v) = %v, want %v", tc.ticket, got, tc.want)
			}
		})
	}
}

func TestCMRequiredForCommand(t *testing.T) {
	t.Setenv("ADSSH_CM_PATTERNS", "rm,kubectl*")

	cases := []struct {
		cmd  string
		want bool
	}{
		{"rm", true},
		{"/bin/rm", true}, // basename match
		{"kubectl", true},
		{"ls", false},
	}
	for _, tc := range cases {
		if got := CMRequiredForCommand(tc.cmd); got != tc.want {
			t.Errorf("CMRequiredForCommand(%q) = %v, want %v", tc.cmd, got, tc.want)
		}
	}

	t.Setenv("ADSSH_CM_PATTERNS", "")
	if CMRequiredForCommand("rm") {
		t.Error("expected CMRequiredForCommand to always return false with empty ADSSH_CM_PATTERNS")
	}
}

func TestCMSessionCheck_StrictBlocks(t *testing.T) {
	ClearActiveCMTicket()
	t.Cleanup(ClearActiveCMTicket)

	t.Setenv("ADSSH_CM_PATTERNS", "rm,kubectl*")

	// Strict mode, no active ticket -> blocked.
	t.Setenv("ADSSH_CM_STRICT", "1")
	if err := CMSessionCheck("rm", nil); err == nil {
		t.Error("expected error in strict mode with no active ticket")
	}

	// Non-strict mode, no active ticket -> warn but don't block.
	t.Setenv("ADSSH_CM_STRICT", "0")
	if err := CMSessionCheck("rm", nil); err != nil {
		t.Errorf("expected nil error in non-strict mode with no active ticket, got: %v", err)
	}

	// Valid active ticket -> allowed regardless of strict mode.
	t.Setenv("ADSSH_CM_STRICT", "1")
	SetActiveCMTicket(&CMTicket{ID: "CHG1", State: "approved"}, "CHG1")
	if err := CMSessionCheck("rm", nil); err != nil {
		t.Errorf("expected nil error with valid active ticket, got: %v", err)
	}

	// Invalid ticket state -> blocked.
	SetActiveCMTicket(&CMTicket{ID: "CHG2", State: "open"}, "CHG2")
	if err := CMSessionCheck("rm", nil); err == nil {
		t.Error("expected error with invalid ticket state")
	}

	// Command not covered by patterns -> always a no-op.
	ClearActiveCMTicket()
	if err := CMSessionCheck("ls", nil); err != nil {
		t.Errorf("expected nil for non-matching command, got: %v", err)
	}
}

func TestChangeTicketStateIsIsolatedBySession(t *testing.T) {
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	ticket := &CMTicket{ID: "CHG-A", State: "approved"}
	eng.SetActiveCMTicketForSession("session-a", ticket, ticket.ID)

	if got, id := eng.GetActiveCMTicketForSession("session-a"); got != ticket || id != ticket.ID {
		t.Fatalf("session A ticket = (%v, %q), want its configured ticket", got, id)
	}
	if got, id := eng.GetActiveCMTicketForSession("session-b"); got != nil || id != "" {
		t.Fatalf("session B inherited session A ticket: (%v, %q)", got, id)
	}
	eng.ClearActiveCMTicketForSession("session-b")
	if got, _ := eng.GetActiveCMTicketForSession("session-a"); got == nil {
		t.Fatal("clearing session B removed session A ticket")
	}
}

func TestFetchCMTicket_Generic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tickets/CHG-1":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"id":       "CHG-1",
				"title":    "Test change",
				"state":    "approved",
				"assignee": "alice",
			})
		case "/tickets/CHG-500":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("boom"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("ADSSH_CM_URL", srv.URL)
	t.Setenv("ADSSH_CM_PROVIDER", "generic")

	ticket, err := FetchCMTicket("CHG-1")
	if err != nil {
		t.Fatalf("FetchCMTicket: %v", err)
	}
	if ticket.ID != "CHG-1" || ticket.Title != "Test change" || ticket.State != "approved" || ticket.Assignee != "alice" || ticket.Provider != "generic" {
		t.Errorf("unexpected ticket: %+v", ticket)
	}

	if _, err := FetchCMTicket("CHG-500"); err == nil {
		t.Error("expected error on HTTP 500")
	}

	t.Setenv("ADSSH_CM_URL", "")
	if _, err := FetchCMTicket("CHG-1"); err == nil {
		t.Error("expected error when ADSSH_CM_URL is unset")
	} else if !strings.Contains(err.Error(), "ADSSH_CM_URL") {
		t.Errorf("expected error to mention ADSSH_CM_URL, got: %v", err)
	}
}

func TestFetchCMTicket_UnknownProvider(t *testing.T) {
	t.Setenv("ADSSH_CM_URL", "http://example.invalid")
	t.Setenv("ADSSH_CM_PROVIDER", "bogus")

	_, err := FetchCMTicket("CHG-1")
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
	if !strings.Contains(err.Error(), "unknown provider") || !strings.Contains(err.Error(), "bogus") {
		t.Errorf("expected descriptive unknown-provider error, got: %v", err)
	}
}
