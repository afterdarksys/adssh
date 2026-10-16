package starlarkext

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"go.starlark.net/starlark"
)

// Threats: notify.teams POSTs operator text to a Microsoft Teams webhook
// (Workflows "When a Teams webhook request is received", or a legacy
// Microsoft 365 connector URL). The URL is a bearer secret and a possible SSRF
// lever. validateTeamsURL accepts only https on the default port to a DNS
// name: no userinfo, no literal IPs, no localhost or metadata names. The
// client re-checks the address it actually connects to and refuses loopback,
// private (RFC1918, CGNAT, ULA), link-local, metadata, multicast, and
// unspecified addresses, so DNS rebinding to an internal host fails at
// connect time; NAT64 (64:ff9b::/96), 0.0.0.0/8 and 198.18.0.0/15 are
// refused too. Proxies are not used, redirects are refused, TLS is 1.3 with
// the system roots, the request has a 10s timeout, the card is capped at the
// Teams 28 KB message limit, and at most 4 KB of the response is read. Errors
// never contain the URL. It does not stop a public host the operator named
// from receiving the text, and a URL passed as an argument is visible to the
// policy gate and the audit log; set TEAMS_WEBHOOK_URL to keep it out of
// both. In restricted sessions notify.teams is absent.

// ExpandNotifyAPI adds the teams key to the existing notify.* dict. In
// restricted sessions it adds nothing.
//
// Starlark API:
//
//	notify.teams(webhook_url="", title=, text="", color="")
//
// title is required. webhook_url "" or omitted falls back to the TEAMS_WEBHOOK_URL env var. color is an
// Adaptive Card text color: default, dark, light, accent, good, warning,
// attention.
func ExpandNotifyAPI(env starlark.StringDict, restricted bool) {
	if restricted {
		return
	}
	notifyDict, ok := env["notify"].(*starlark.Dict)
	if !ok {
		return
	}
	_ = notifyDict.SetKey(starlark.String("teams"), starlark.NewBuiltin("teams", notifyTeams))
}

// ── Microsoft Teams ───────────────────────────────────────────────────────────

const (
	teamsTimeout      = 10 * time.Second
	teamsMaxPayload   = 28 * 1024
	teamsMaxResponse  = 4 * 1024
	teamsMaxURLLength = 2048
)

var errTeamsURL = errors.New("webhook_url must be an https URL to a public DNS name")

var errTeamsDial = errors.New("dial_denied")

var teamsColors = map[string]string{
	"default": "Default", "dark": "Dark", "light": "Light", "accent": "Accent",
	"good": "Good", "warning": "Warning", "attention": "Attention",
}

// validateTeamsURL checks the webhook URL without touching the network.
// Tests replace it to reach an httptest server.
var validateTeamsURL = func(raw string) error {
	if raw == "" || len(raw) > teamsMaxURLLength || strings.ContainsAny(raw, "\r\n\x00") {
		return errTeamsURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" {
		return errTeamsURL
	}
	if p := u.Port(); p != "" && p != "443" {
		return errTeamsURL
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return errTeamsURL
	}
	switch {
	case host == "localhost", strings.HasSuffix(host, ".localhost"),
		host == "metadata.google.internal", host == "metadata.goog",
		strings.HasSuffix(host, ".internal"), strings.HasSuffix(host, ".local"):
		return errTeamsURL
	}
	return nil
}

// teamsIPBlocked reports addresses notify.teams must never connect to.
func teamsIPBlocked(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	for _, n := range teamsBlockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return ip.Equal(net.ParseIP("fd00:ec2::254"))
}

// teamsBlockedNets are ranges the net.IP predicates above do not cover.
var teamsBlockedNets = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, cidr := range []string{
		"100.64.0.0/10", // CGNAT
		"0.0.0.0/8",     // "this network"
		"198.18.0.0/15", // benchmarking
		"64:ff9b::/96",  // NAT64: reaches any IPv4 address, internal ones included
	} {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		nets = append(nets, n)
	}
	return nets
}()

// teamsDialControl refuses a connection to a blocked address after DNS.
func teamsDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil || teamsIPBlocked(net.ParseIP(host)) {
		return errTeamsDial
	}
	return nil
}

// teamsHTTPClient builds the client notify.teams posts with. Tests replace it.
var teamsHTTPClient = func() *http.Client {
	dialer := &net.Dialer{Timeout: teamsTimeout, Control: teamsDialControl}
	return &http.Client{
		Timeout: teamsTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   teamsTimeout,
			ResponseHeaderTimeout: teamsTimeout,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS13},
		},
	}
}

// teamsCard builds the Adaptive Card message envelope that both Workflows
// webhooks and legacy incoming webhooks accept.
func teamsCard(title, text, color string) map[string]interface{} {
	titleBlock := map[string]interface{}{
		"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "wrap": true,
	}
	if color != "" {
		titleBlock["color"] = color
	}
	body := []interface{}{titleBlock}
	if text != "" {
		body = append(body, map[string]interface{}{"type": "TextBlock", "text": text, "wrap": true})
	}
	return map[string]interface{}{
		"type": "message",
		"attachments": []interface{}{map[string]interface{}{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"contentUrl":  nil,
			"content": map[string]interface{}{
				"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
				"type":    "AdaptiveCard",
				"version": "1.4",
				"body":    body,
			},
		}},
	}
}

func notifyTeams(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	const op = "notify.teams"
	var webhookURL, title, text, color string
	// Every parameter is optional to UnpackArgs so notify.teams(title=, text=)
	// works with the URL from TEAMS_WEBHOOK_URL; title is checked below.
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"webhook_url?", &webhookURL,
		"title?", &title,
		"text?", &text,
		"color?", &color,
	); err != nil {
		return nil, err
	}
	if webhookURL == "" {
		webhookURL = os.Getenv("TEAMS_WEBHOOK_URL")
	}
	if webhookURL == "" {
		return nil, fmt.Errorf("%s: no webhook_url provided and TEAMS_WEBHOOK_URL not set", op)
	}
	if err := validateTeamsURL(webhookURL); err != nil {
		return nil, fmt.Errorf("%s: %v", op, err)
	}
	if title == "" {
		return nil, fmt.Errorf("%s: title is required", op)
	}
	cardColor := ""
	if color != "" {
		var ok bool
		if cardColor, ok = teamsColors[strings.ToLower(color)]; !ok {
			return nil, fmt.Errorf("%s: unknown color %q (want default, dark, light, accent, good, warning, attention)", op, color)
		}
	}

	body, err := json.Marshal(teamsCard(title, text, cardColor))
	if err != nil {
		return nil, fmt.Errorf("%s: marshal: %v", op, err)
	}
	if len(body) > teamsMaxPayload {
		return nil, fmt.Errorf("%s: card is %d bytes, Teams limit is %d", op, len(body), teamsMaxPayload)
	}

	ctx, cancel := context.WithTimeout(context.Background(), teamsTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%s: invalid request", op)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := teamsHTTPClient().Do(req)
	if err != nil {
		return nil, cloudError(op, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, teamsMaxResponse))
	if err != nil {
		return nil, cloudError(op+": read response", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s: HTTP %d: %s", op, resp.StatusCode, cleanErrorText(string(respBody)))
	}
	return makeDict("status", int64(resp.StatusCode)), nil
}
