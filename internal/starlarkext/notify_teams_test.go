package starlarkext

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

type countingTransport struct{ posts *int }

func (c countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	*c.posts++
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("1")), Header: http.Header{}}, nil
}

// installTeamsFake replaces the Teams HTTP client with one that counts posts
// and never touches the network.
func installTeamsFake(t *testing.T) *int {
	t.Helper()
	posts := new(int)
	old := teamsHTTPClient
	teamsHTTPClient = func() *http.Client { return &http.Client{Transport: countingTransport{posts}} }
	t.Cleanup(func() { teamsHTTPClient = old })
	return posts
}

// teamsTestServer starts a TLS server and points notify.teams at it: the URL
// check is relaxed for its loopback address and its client trusts its cert,
// with redirects still refused.
func teamsTestServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	oldValidate, oldClient := validateTeamsURL, teamsHTTPClient
	validateTeamsURL = func(raw string) error {
		if strings.HasPrefix(raw, srv.URL) {
			return nil
		}
		return oldValidate(raw)
	}
	teamsHTTPClient = func() *http.Client {
		c := srv.Client()
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return c
	}
	t.Cleanup(func() { validateTeamsURL, teamsHTTPClient = oldValidate, oldClient })
	return srv
}

func TestTeamsPostsAdaptiveCard(t *testing.T) {
	var got map[string]interface{}
	var contentType string
	srv := teamsTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	})
	env := cloudEnv(t, allowAllPolicy, false)
	env["URL"] = starlark.String(srv.URL + "/workflows/hook?sig=abc")
	v, err := evalCloud(t, env, `notify["teams"](URL, "Deploy", "v1.2 is live", color="Good")`)
	if err != nil {
		t.Fatalf("teams: %v", err)
	}
	if dictGet(t, v, "status") != starlark.MakeInt(202) || contentType != "application/json" {
		t.Fatalf("result = %v content-type %q", v, contentType)
	}
	att := got["attachments"].([]interface{})[0].(map[string]interface{})
	card := att["content"].(map[string]interface{})
	body := card["body"].([]interface{})
	title := body[0].(map[string]interface{})
	if got["type"] != "message" || att["contentType"] != "application/vnd.microsoft.card.adaptive" ||
		card["type"] != "AdaptiveCard" || title["text"] != "Deploy" || title["color"] != "Good" ||
		body[1].(map[string]interface{})["text"] != "v1.2 is live" {
		t.Fatalf("payload = %v", got)
	}
}

func TestTeamsEnvFallback(t *testing.T) {
	hit := false
	srv := teamsTestServer(t, func(w http.ResponseWriter, r *http.Request) { hit = true })
	t.Setenv("TEAMS_WEBHOOK_URL", srv.URL+"/hook")
	if _, err := evalCloud(t, cloudEnv(t, allowAllPolicy, false), `notify["teams"]("", "t", "x")`); err != nil || !hit {
		t.Fatalf("err = %v hit = %v", err, hit)
	}
}

func TestTeamsRejectsBadURLs(t *testing.T) {
	posts := installTeamsFake(t)
	env := cloudEnv(t, allowAllPolicy, false)
	for _, u := range []string{
		"http://example.webhook.office.com/x",
		"https://user:pw@example.webhook.office.com/x",
		"https://127.0.0.1/x",
		"https://[::1]/x",
		"https://10.0.0.5/x",
		"https://169.254.169.254/latest/meta-data",
		"https://localhost/x",
		"https://metadata.google.internal/x",
		"https://svc.cluster.local/x",
		"https://intranet/x",
		"https://example.webhook.office.com:8443/x",
		"https://example.webhook.office.com/x\r\nX-Injected: 1",
		"https://example.webhook.office.com/" + strings.Repeat("a", teamsMaxURLLength),
		"ftp://example.webhook.office.com/x",
	} {
		env["URL"] = starlark.String(u)
		_, err := evalCloud(t, env, `notify["teams"](URL, "t", "x")`)
		if err == nil || !strings.Contains(err.Error(), "https URL to a public DNS name") {
			t.Fatalf("%q: err = %v, want URL rejection", u, err)
		}
	}
	if *posts != 0 {
		t.Fatalf("posted %d times for rejected URLs", *posts)
	}
}

func TestTeamsRejectsBadInput(t *testing.T) {
	posts := installTeamsFake(t)
	env := cloudEnv(t, allowAllPolicy, false)
	env["BIG"] = starlark.String(strings.Repeat("x", teamsMaxPayload))
	for expr, want := range map[string]string{
		`notify["teams"]("https://a.webhook.office.com/x", "t", "x", color="#ff0000")`: "unknown color",
		`notify["teams"]("https://a.webhook.office.com/x", "t", BIG)`:                  "Teams limit",
		`notify["teams"]("https://a.webhook.office.com/x", "", "x")`:                   "title is required",
	} {
		if _, err := evalCloud(t, env, expr); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: err = %v, want %q", expr, err, want)
		}
	}
	t.Setenv("TEAMS_WEBHOOK_URL", "")
	if _, err := evalCloud(t, env, `notify["teams"]("", "t", "x")`); err == nil || !strings.Contains(err.Error(), "TEAMS_WEBHOOK_URL") {
		t.Fatalf("err = %v, want missing URL", err)
	}
	if *posts != 0 {
		t.Fatalf("posted %d times for rejected input", *posts)
	}
}

func TestTeamsErrorIsCappedAndHidesURL(t *testing.T) {
	srv := teamsTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad card\n" + strings.Repeat("y", 10000)))
	})
	env := cloudEnv(t, allowAllPolicy, false)
	env["URL"] = starlark.String(srv.URL + "/hook?sig=SECRETSIG")
	_, err := evalCloud(t, env, `notify["teams"](URL, "t", "x")`)
	if err == nil || !strings.Contains(err.Error(), "HTTP 400: bad card") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "SECRETSIG") || strings.Contains(err.Error(), "\n") || len(err.Error()) > 400 {
		t.Fatalf("error leaks the URL, a newline, or is uncapped (%d bytes)", len(err.Error()))
	}
}

func TestTeamsRefusesRedirect(t *testing.T) {
	srv := teamsTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://169.254.169.254/latest", http.StatusFound)
	})
	env := cloudEnv(t, allowAllPolicy, false)
	env["URL"] = starlark.String(srv.URL + "/hook")
	if _, err := evalCloud(t, env, `notify["teams"](URL, "t", "x")`); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("err = %v, want redirect refused", err)
	}
}

// The production client refuses to connect to loopback even when the URL
// check is bypassed, so DNS rebinding to an internal address fails closed.
func TestTeamsClientRefusesInternalAddressAtDial(t *testing.T) {
	hit := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()
	old := validateTeamsURL
	validateTeamsURL = func(string) error { return nil }
	t.Cleanup(func() { validateTeamsURL = old })
	env := cloudEnv(t, allowAllPolicy, false)
	env["URL"] = starlark.String(srv.URL + "/hook?sig=SECRETSIG")
	_, err := evalCloud(t, env, `notify["teams"](URL, "t", "x")`)
	if err == nil || !strings.Contains(err.Error(), "dial_denied") || hit {
		t.Fatalf("err = %v hit = %v, want dial_denied", err, hit)
	}
	if strings.Contains(err.Error(), "SECRETSIG") {
		t.Fatalf("error leaks the webhook URL: %v", err)
	}
}

func TestTeamsDialControl(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1:443", "10.1.2.3:443", "172.16.0.1:443", "192.168.1.1:443", "100.64.0.1:443",
		"169.254.169.254:443", "0.0.0.0:443", "224.0.0.1:443", "[::1]:443", "[fd00:ec2::254]:443",
		"[fe80::1]:443", "[fc00::1]:443", "not-an-address",
	} {
		if err := teamsDialControl("tcp", addr, nil); err == nil {
			t.Fatalf("%s: allowed, want dial_denied", addr)
		}
	}
	for _, addr := range []string{"52.96.0.1:443", "[2603:1036::1]:443"} {
		if err := teamsDialControl("tcp", addr, nil); err != nil {
			t.Fatalf("%s: %v, want allowed", addr, err)
		}
	}
}

// NAT64 can reach any IPv4 address, internal ones included; 0.0.0.0/8 and the
// 198.18.0.0/15 benchmark range are not public destinations either.
func TestTeamsDialControlBlocksNAT64AndReserved(t *testing.T) {
	for _, addr := range []string{
		"[64:ff9b::7f00:1]:443", "[64:ff9b::a9fe:a9fe]:443", "[64:ff9b::3460:1]:443",
		"0.1.2.3:443", "198.18.0.1:443", "198.19.255.255:443",
	} {
		if err := teamsDialControl("tcp", addr, nil); err == nil {
			t.Fatalf("%s: allowed, want dial_denied", addr)
		}
	}
	for _, addr := range []string{"198.17.255.255:443", "198.20.0.1:443", "[64:ff9c::1]:443"} {
		if err := teamsDialControl("tcp", addr, nil); err != nil {
			t.Fatalf("%s: %v, want allowed", addr, err)
		}
	}
}

// The URL argument is optional again: keywords alone, with the URL from
// TEAMS_WEBHOOK_URL, post the card.
func TestTeamsKeywordsWithEnvURL(t *testing.T) {
	var got map[string]interface{}
	srv := teamsTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
	})
	t.Setenv("TEAMS_WEBHOOK_URL", srv.URL+"/hook")
	env := cloudEnv(t, allowAllPolicy, false)
	for _, expr := range []string{
		`notify["teams"](title="deploy", text="done")`,
		`notify["teams"](title="deploy")`,
		`notify["teams"](webhook_url="", title="deploy", text="done", color="good")`,
	} {
		got = nil
		if _, err := evalCloud(t, env, expr); err != nil || got == nil {
			t.Fatalf("%s: err = %v posted = %v", expr, err, got != nil)
		}
	}
	if _, err := evalCloud(t, env, `notify["teams"](text="no title")`); err == nil || !strings.Contains(err.Error(), "title") {
		t.Fatalf("err = %v, want title required", err)
	}
}
