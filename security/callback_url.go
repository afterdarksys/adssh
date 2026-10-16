package security

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Threats: operator-supplied callback, control-plane, JWKS, and audit webhook
// URLs can point at link-local metadata services, private (RFC1918, CGNAT
// 100.64/10, ULA fc00::/7) hosts, plaintext off-box hosts, or redirects that
// move a bearer. validateCallbackURL refuses those before a dial. The control
// plane and identity providers are public origins, so private ranges are
// blocked unless the operator sets ADSSH_CALLBACK_ALLOW_PRIVATE=1 (default
// off); that override never admits metadata, link-local, multicast, or
// unspecified addresses. callbackHTTPClient re-checks the address actually
// connected to in Dialer.Control, so a DNS answer that changes after
// validation (rebinding) is refused at connect time. Redirects are refused.
// TLS is 1.3 with the system CA pool. Every DNS lookup here is bounded by
// callbackResolveTimeout, so slow DNS fails the request instead of hanging it.
// A rejection keeps the "url_rejected" text and wraps errPrivateHost or
// errHostUnresolved so callers can name the cause without changing codes.
// This does not pin a certificate, and it does not stop a public host that
// the operator configured from lying.

var errRedirectDenied = errors.New("redirect_denied")

var errDialDenied = errors.New("dial_denied")

// errPrivateHost marks a rejection whose only cause is a private (RFC1918,
// CGNAT, ULA) address that ADSSH_CALLBACK_ALLOW_PRIVATE=1 would admit.
var errPrivateHost = errors.New("private_host")

// errHostUnresolved marks a rejection because the host did not resolve.
var errHostUnresolved = errors.New("host_unresolved")

// urlRejectedError keeps the "url_rejected" text that callers and tests match
// on, and carries the cause for errors.Is.
type urlRejectedError struct{ cause error }

func (e urlRejectedError) Error() string { return "url_rejected" }
func (e urlRejectedError) Unwrap() error { return e.cause }

var errURLRejected = urlRejectedError{}

// callbackResolveTimeout bounds every host lookup in this file.
const callbackResolveTimeout = 5 * time.Second

// callbackLookupIP resolves a host. Tests replace it to run without DNS.
var callbackLookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// callbackTLSRoots overrides the system CA pool. Only tests set it, to trust
// an httptest TLS server. Nil means the system pool.
var callbackTLSRoots atomic.Pointer[x509.CertPool]

var cgnatBlock = &net.IPNet{IP: net.IPv4(100, 64, 0, 0).To4(), Mask: net.CIDRMask(10, 32)}

// validateCallbackURLSyntax checks everything validateCallbackURL checks
// except DNS: scheme, userinfo, host, blocked names, and literal IPs. It never
// touches the network.
func validateCallbackURLSyntax(raw string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > 2048 || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, errURLRejected
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil {
		return nil, errURLRejected
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "localhost" || host == "metadata.google.internal" || host == "metadata.goog" {
		return nil, errURLRejected
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !exactLoopbackHost(host) {
			return nil, errURLRejected
		}
	default:
		return nil, errURLRejected
	}
	if ip := net.ParseIP(host); ip != nil {
		if callbackIPNeedsPrivateOverride(ip) {
			return nil, urlRejectedError{cause: errPrivateHost}
		}
		if callbackIPBlocked(ip) || (ip.IsLoopback() && !exactLoopbackHost(host)) {
			return nil, errURLRejected
		}
	}
	return parsed, nil
}

func validateCallbackURL(raw string) (*url.URL, error) {
	parsed, err := validateCallbackURLSyntax(raw)
	if err != nil {
		return nil, err
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if net.ParseIP(host) != nil {
		return parsed, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), callbackResolveTimeout)
	defer cancel()
	addrs, err := callbackLookupIP(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil, urlRejectedError{cause: errHostUnresolved}
	}
	if err := checkResolvedIPs(addrs); err != nil {
		return nil, urlRejectedError{cause: err}
	}
	return parsed, nil
}

// checkResolvedIPs refuses a lookup answer that holds any blocked address.
// An always-blocked address (metadata, link-local, loopback) wins over a
// private one, so the override is only suggested when it would help.
func checkResolvedIPs(addrs []net.IP) error {
	private := false
	for _, addr := range addrs {
		if callbackIPNeedsPrivateOverride(addr) {
			private = true
			continue
		}
		if callbackIPBlocked(addr) || addr.IsLoopback() {
			return errDialDenied
		}
	}
	if private {
		return errPrivateHost
	}
	return nil
}

func exactLoopbackHost(host string) bool {
	return host == "127.0.0.1" || host == "::1"
}

func callbackAllowPrivate() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ADSSH_CALLBACK_ALLOW_PRIVATE"))) {
	case "1", "true", "yes":
		return true
	}
	return false
}

func callbackIPBlocked(ip net.IP) bool {
	if callbackIPAlwaysBlocked(ip) {
		return true
	}
	if ip.IsPrivate() || cgnatBlock.Contains(ip) {
		return !callbackAllowPrivate()
	}
	return false
}

// callbackIPAlwaysBlocked reports addresses the private override never admits.
func callbackIPAlwaysBlocked(ip net.IP) bool {
	if ip == nil || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil && ip4.Equal(net.IPv4(169, 254, 169, 254)) {
		return true
	}
	return ip.Equal(net.ParseIP("fd00:ec2::254"))
}

// callbackIPNeedsPrivateOverride reports a private address that is refused
// only because ADSSH_CALLBACK_ALLOW_PRIVATE is not set.
func callbackIPNeedsPrivateOverride(ip net.IP) bool {
	return ip != nil && !callbackIPAlwaysBlocked(ip) && (ip.IsPrivate() || cgnatBlock.Contains(ip)) && !callbackAllowPrivate()
}

// callbackDialContext dials addr and validates the IP actually connected to.
// Loopback is admitted only when addr names a literal loopback IP, which
// validateCallbackURL has already restricted to the exact forms it allows.
func callbackDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errDialDenied
	}
	literalLoopback := exactLoopbackHost(host)
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			connected, _, err := net.SplitHostPort(address)
			if err != nil {
				return errDialDenied
			}
			ip := net.ParseIP(connected)
			if ip == nil || callbackIPBlocked(ip) || (ip.IsLoopback() && !literalLoopback) {
				return errDialDenied
			}
			return nil
		},
	}
	return dialer.DialContext(ctx, network, addr)
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
			DialContext:           callbackDialContext,
			ResponseHeaderTimeout: timeout,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    callbackTLSRoots.Load(),
			},
		},
	}
}

func fingerprintSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
