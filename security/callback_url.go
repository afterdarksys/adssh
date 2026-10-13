package security

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Threats: operator-supplied callback and approval URLs can point at
// link-local metadata services, plaintext off-box hosts, or redirects that
// move a bearer. validateCallbackURL refuses those before a dial. DNS answers
// are checked once and can change afterward. This does not pin a certificate.
// Redirects are refused. TLS is 1.3 with the system CA pool.

var errRedirectDenied = errors.New("redirect_denied")

func validateCallbackURL(raw string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > 2048 || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, errors.New("url_rejected")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil {
		return nil, errors.New("url_rejected")
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "localhost" || host == "metadata.google.internal" || host == "metadata.goog" {
		return nil, errors.New("url_rejected")
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !exactLoopbackHost(host) {
			return nil, errors.New("url_rejected")
		}
	default:
		return nil, errors.New("url_rejected")
	}
	if ip := net.ParseIP(host); ip != nil {
		if callbackIPBlocked(ip) || (ip.IsLoopback() && !exactLoopbackHost(host)) {
			return nil, errors.New("url_rejected")
		}
		return parsed, nil
	}
	addrs, err := net.LookupIP(host)
	if err != nil || len(addrs) == 0 {
		return nil, errors.New("url_rejected")
	}
	for _, addr := range addrs {
		if callbackIPBlocked(addr) || addr.IsLoopback() {
			return nil, errors.New("url_rejected")
		}
	}
	return parsed, nil
}

func exactLoopbackHost(host string) bool {
	return host == "127.0.0.1" || host == "::1"
}

func callbackIPBlocked(ip net.IP) bool {
	if ip == nil || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil && ip4.Equal(net.IPv4(169, 254, 169, 254)) {
		return true
	}
	if ip.Equal(net.ParseIP("fd00:ec2::254")) {
		return true
	}
	return false
}

func callbackHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirectDenied
		},
		Transport: &http.Transport{
			Proxy:                 nil,
			ResponseHeaderTimeout: timeout,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
			},
		},
	}
}

func fingerprintSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
