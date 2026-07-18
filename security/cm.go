package security

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CMTicket is the normalised view of a change ticket from any provider.
type CMTicket struct {
	ID          string
	Title       string
	State       string // "approved", "open", "closed", "unknown"
	Assignee    string
	StartWindow time.Time
	EndWindow   time.Time
	Provider    string
}

// cmHTTPClient returns an HTTP client with a 10-second timeout.
func cmHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

// cmBaseURL returns ADSSH_CM_URL or an error if not set.
func cmBaseURL() (string, error) {
	u := os.Getenv("ADSSH_CM_URL")
	if u == "" {
		return "", fmt.Errorf("cm: ADSSH_CM_URL not configured")
	}
	return strings.TrimRight(u, "/"), nil
}

// cmBearerToken returns the value of ADSSH_CM_TOKEN without logging it.
func cmBearerToken() string {
	return os.Getenv("ADSSH_CM_TOKEN")
}

// cmDoGET performs a GET request with Bearer auth and decodes the JSON body.
func cmDoGET(url string, target interface{}) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("cm: build request: %w", err)
	}
	if tok := cmBearerToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := cmHTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("cm: request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("cm: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("cm: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("cm: decode response: %w", err)
	}
	return nil
}

// fetchServiceNow fetches a change ticket from ServiceNow.
// GET {ADSSH_CM_URL}/api/now/table/change_request?sysparm_query=number={id}
func fetchServiceNow(id string) (*CMTicket, error) {
	base, err := cmBaseURL()
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/api/now/table/change_request?sysparm_query=number=%s", base, id)

	var envelope struct {
		Result []struct {
			Number     string `json:"number"`
			ShortDesc  string `json:"short_description"`
			State      string `json:"state"`
			AssignedTo struct {
				DisplayValue string `json:"display_value"`
			} `json:"assigned_to"`
			StartDate string `json:"start_date"`
			EndDate   string `json:"end_date"`
		} `json:"result"`
	}

	if err := cmDoGET(url, &envelope); err != nil {
		return nil, err
	}
	if len(envelope.Result) == 0 {
		return nil, fmt.Errorf("cm: ticket %s not found in ServiceNow", id)
	}
	r := envelope.Result[0]

	// State mapping
	var state string
	switch r.State {
	case "approved", "implement":
		state = "approved"
	case "closed":
		state = "closed"
	default:
		state = "open"
	}

	t := &CMTicket{
		ID:       r.Number,
		Title:    r.ShortDesc,
		State:    state,
		Assignee: r.AssignedTo.DisplayValue,
		Provider: "servicenow",
	}
	// Parse optional time windows (format: "2006-01-02 15:04:05")
	const snLayout = "2006-01-02 15:04:05"
	if r.StartDate != "" {
		if ts, err := time.Parse(snLayout, r.StartDate); err == nil {
			t.StartWindow = ts
		}
	}
	if r.EndDate != "" {
		if ts, err := time.Parse(snLayout, r.EndDate); err == nil {
			t.EndWindow = ts
		}
	}
	return t, nil
}

// fetchJira fetches a change ticket from Jira.
// GET {ADSSH_CM_URL}/rest/api/2/issue/{id}
func fetchJira(id string) (*CMTicket, error) {
	base, err := cmBaseURL()
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/rest/api/2/issue/%s", base, id)

	var issue struct {
		Key    string `json:"key"`
		Fields struct {
			Summary string `json:"summary"`
			Status  struct {
				Name string `json:"name"`
			} `json:"status"`
			Assignee struct {
				EmailAddress string `json:"emailAddress"`
				DisplayName  string `json:"displayName"`
			} `json:"assignee"`
		} `json:"fields"`
	}

	if err := cmDoGET(url, &issue); err != nil {
		return nil, err
	}

	// State mapping
	var state string
	switch issue.Fields.Status.Name {
	case "In Progress":
		state = "approved"
	case "Done", "Closed":
		state = "closed"
	default:
		state = "open"
	}

	assignee := issue.Fields.Assignee.EmailAddress
	if assignee == "" {
		assignee = issue.Fields.Assignee.DisplayName
	}

	return &CMTicket{
		ID:       issue.Key,
		Title:    issue.Fields.Summary,
		State:    state,
		Assignee: assignee,
		Provider: "jira",
	}, nil
}

// fetchGeneric fetches a change ticket from a generic REST endpoint.
// GET {ADSSH_CM_URL}/tickets/{id}
// Expects JSON with fields: id, title, state, assignee.
func fetchGeneric(id string) (*CMTicket, error) {
	base, err := cmBaseURL()
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/tickets/%s", base, id)

	var body struct {
		ID       string `json:"id"`
		Title    string `json:"title"`
		State    string `json:"state"`
		Assignee string `json:"assignee"`
	}

	if err := cmDoGET(url, &body); err != nil {
		return nil, err
	}

	return &CMTicket{
		ID:       body.ID,
		Title:    body.Title,
		State:    body.State,
		Assignee: body.Assignee,
		Provider: "generic",
	}, nil
}

// FetchCMTicket dispatches to the right provider based on ADSSH_CM_PROVIDER.
// If ADSSH_CM_PROVIDER or ADSSH_CM_URL is empty, it returns a descriptive error.
func FetchCMTicket(id string) (*CMTicket, error) {
	if _, err := cmBaseURL(); err != nil {
		return nil, err
	}
	provider := os.Getenv("ADSSH_CM_PROVIDER")
	if provider == "" {
		provider = "generic"
	}
	switch provider {
	case "servicenow":
		return fetchServiceNow(id)
	case "jira":
		return fetchJira(id)
	case "generic":
		return fetchGeneric(id)
	default:
		return nil, fmt.Errorf("cm: unknown provider %q — set ADSSH_CM_PROVIDER to servicenow, jira, or generic", provider)
	}
}

// IsTicketValid returns true when the ticket state is "approved" and (if a
// time window is set) the current time is within the window.
func IsTicketValid(t *CMTicket) bool {
	if t == nil {
		return false
	}
	if t.State != "approved" {
		return false
	}
	now := time.Now()
	if !t.StartWindow.IsZero() {
		if now.Before(t.StartWindow) {
			return false
		}
	}
	if !t.EndWindow.IsZero() {
		if now.After(t.EndWindow) {
			return false
		}
	}
	return true
}

// Active CM ticket session state — now held on the Engine.

// SetActiveCMTicket stores t as the active CM ticket for this session.
func (e *Engine) SetActiveCMTicket(t *CMTicket, id string) {
	e.cmMu.Lock()
	defer e.cmMu.Unlock()
	e.activeCMTicket = t
	e.activeCMID = id
}

// SetActiveCMTicket stores t as the active CM ticket for this session.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func SetActiveCMTicket(t *CMTicket, id string) {
	defaultEngine.SetActiveCMTicket(t, id)
}

// GetActiveCMTicket returns the active CM ticket and its ID.
func (e *Engine) GetActiveCMTicket() (*CMTicket, string) {
	e.cmMu.Lock()
	defer e.cmMu.Unlock()
	return e.activeCMTicket, e.activeCMID
}

// GetActiveCMTicket returns the active CM ticket and its ID.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func GetActiveCMTicket() (*CMTicket, string) {
	return defaultEngine.GetActiveCMTicket()
}

// ClearActiveCMTicket removes the active CM ticket from the session.
func (e *Engine) ClearActiveCMTicket() {
	e.cmMu.Lock()
	defer e.cmMu.Unlock()
	e.activeCMTicket = nil
	e.activeCMID = ""
}

// ClearActiveCMTicket removes the active CM ticket from the session.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func ClearActiveCMTicket() {
	defaultEngine.ClearActiveCMTicket()
}

// CMRequiredForCommand checks whether cmd matches any pattern in
// ADSSH_CM_PATTERNS (comma-separated, filepath.Match globs).
func CMRequiredForCommand(cmd string) bool {
	// TODO(engine-config): read from EngineConfig instead of the process env.
	raw := os.Getenv("ADSSH_CM_PATTERNS")
	if raw == "" {
		return false
	}
	base := filepath.Base(cmd)
	for _, pat := range strings.Split(raw, ",") {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if matched, _ := filepath.Match(pat, cmd); matched {
			return true
		}
		if matched, _ := filepath.Match(pat, base); matched {
			return true
		}
	}
	return false
}

// CMStrictMode returns true when ADSSH_CM_STRICT=1.
func CMStrictMode() bool {
	// TODO(engine-config): read from EngineConfig instead of the process env.
	return os.Getenv("ADSSH_CM_STRICT") == "1"
}
