package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
)

// Threats: a device-login access token is an opaque bearer for its TTL. The
// client refuses plaintext off-box URLs, redirects, metadata hosts, and query
// keys that would place a code in a URL. It writes the token to a 0600 file
// and logs only a SHA-256 fingerprint. It does not treat the bearer as an
// OIDC JWT, clears any previous OIDC provider and eligible roles, and does
// not attach groups. A stolen token file is a bearer until
// it expires. The server, not this client, decides membership.

const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

var deviceUsernamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,128}$`)

type deviceLoginError struct {
	code string
}

func (e deviceLoginError) Error() string { return e.code }

func deviceErr(code string) error { return deviceLoginError{code: code} }

// DeviceLoginRequest starts a username-first device flow against an existing
// control plane. Client may be injected for tests. URL checks always run.
type DeviceLoginRequest struct {
	URL         string
	Username    string
	TokenFile   string
	Interval    time.Duration
	IntervalSet bool
	Timeout     time.Duration
	Client      *http.Client
}

// DeviceLoginResult names the token file and the SHA-256 fingerprint of the
// bearer. It does not carry the bearer or the device code.
type DeviceLoginResult struct {
	TokenFile   string
	Fingerprint string
}

type deviceStartBody struct {
	DeviceCode      string `json:"device_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Error           string `json:"error"`
}

type deviceTokenBody struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
}

// DeviceLogin runs the device flow and stores the opaque bearer. Order is
// session, username, token path, URL, then dial. The session user is set to
// the supplied username with no groups only after the token file is written.
func DeviceLogin(ctx context.Context, req DeviceLoginRequest) (DeviceLoginResult, error) {
	session := sys.GetSession(SessionIDFromContext(ctx))
	if session == nil {
		return DeviceLoginResult{}, fmt.Errorf("identity: requires an active registered session")
	}
	if !deviceUsernamePattern.MatchString(req.Username) {
		return DeviceLoginResult{}, deviceErr("login_denied")
	}
	if req.IntervalSet && req.Interval < 0 {
		return DeviceLoginResult{}, deviceErr("device_login_failed")
	}
	tokenPath, err := deviceTokenPath(req.TokenFile)
	if err != nil {
		return DeviceLoginResult{}, deviceErr("token_file_rejected")
	}
	base, err := validateCallbackURL(req.URL)
	if err != nil {
		return DeviceLoginResult{}, deviceErr("url_rejected")
	}
	base.RawQuery = ""
	base.Fragment = ""

	client := req.Client
	if client == nil {
		client = callbackHTTPClient(15 * time.Second)
	}

	startRaw, status, err := postDeviceForm(ctx, client, endpointURL(base, "/oauth/device"), url.Values{
		"username": {req.Username},
	})
	if err != nil {
		return DeviceLoginResult{}, err
	}
	if code := deviceStatusCode(status, startRaw); code != "" {
		zeroBytes(startRaw)
		return DeviceLoginResult{}, deviceErr(code)
	}
	var start deviceStartBody
	if err := json.Unmarshal(startRaw, &start); err != nil || start.DeviceCode == "" || start.VerificationURL == "" {
		zeroBytes(startRaw)
		return DeviceLoginResult{}, deviceErr("device_login_failed")
	}
	zeroBytes(startRaw)
	if err := checkVerificationURL(base, start.VerificationURL); err != nil {
		return DeviceLoginResult{}, err
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	deadline := time.Now().Add(timeout)
	if start.ExpiresIn > 0 {
		exp := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)
		if exp.Before(deadline) {
			deadline = exp
		}
	}
	interval := 5 * time.Second
	if req.IntervalSet {
		interval = req.Interval
	} else if start.Interval > 0 {
		interval = time.Duration(start.Interval) * time.Second
	}

	deviceCode := start.DeviceCode
	defer func() { deviceCode = "" }()

	for {
		if err := ctx.Err(); err != nil {
			return DeviceLoginResult{}, deviceErr("device_login_failed")
		}
		if time.Now().After(deadline) {
			return DeviceLoginResult{}, deviceErr("expired_token")
		}
		body, pollStatus, err := postDeviceForm(ctx, client, endpointURL(base, "/oauth/token"), url.Values{
			"grant_type":  {deviceGrantType},
			"device_code": {deviceCode},
		})
		if err != nil {
			return DeviceLoginResult{}, err
		}
		if code := deviceStatusCode(pollStatus, body); code != "" {
			zeroBytes(body)
			switch code {
			case "authorization_pending":
				if err := deviceSleep(ctx, deadline, interval); err != nil {
					return DeviceLoginResult{}, err
				}
				continue
			case "slow_down":
				if req.IntervalSet && interval == 0 {
					continue
				}
				interval += 5 * time.Second
				if err := deviceSleep(ctx, deadline, interval); err != nil {
					return DeviceLoginResult{}, err
				}
				continue
			default:
				return DeviceLoginResult{}, deviceErr(code)
			}
		}
		var token deviceTokenBody
		if err := json.Unmarshal(body, &token); err != nil {
			zeroBytes(body)
			return DeviceLoginResult{}, deviceErr("device_login_failed")
		}
		zeroBytes(body)
		if token.TokenType != "Bearer" || token.AccessToken == "" {
			return DeviceLoginResult{}, deviceErr("device_login_failed")
		}
		secret := []byte(token.AccessToken)
		token.AccessToken = ""
		fingerprint := fingerprintSecret(string(secret))
		if err := writeDeviceToken(tokenPath, secret); err != nil {
			zeroBytes(secret)
			return DeviceLoginResult{}, deviceErr("token_file_rejected")
		}
		zeroBytes(secret)
		session.SetIdentity(req.Username, nil)
		session.SetOIDC("", nil)
		engineFromContext(ctx).LogEvent(fmt.Sprintf("IDENTITY_DEVICE_LOGIN user=%s fingerprint=%s", req.Username, fingerprint))
		return DeviceLoginResult{TokenFile: tokenPath, Fingerprint: fingerprint}, nil
	}
}

func deviceTokenPath(path string) (string, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", err
		}
		path = filepath.Join(home, ".adssh", "device.token")
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("relative")
	}
	return path, nil
}

func endpointURL(base *url.URL, path string) string {
	ref, err := url.Parse(path)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(ref)
	resolved.RawQuery = ""
	resolved.Fragment = ""
	return resolved.String()
}

func checkVerificationURL(base *url.URL, raw string) error {
	parsed, err := validateCallbackURL(raw)
	if err != nil {
		return deviceErr("url_rejected")
	}
	if parsed.Scheme != base.Scheme || parsed.Host != base.Host {
		return deviceErr("url_rejected")
	}
	query := parsed.Query()
	if query.Has("device_code") || query.Has("access_token") {
		return deviceErr("url_rejected")
	}
	return nil
}

func postDeviceForm(ctx context.Context, client *http.Client, endpoint string, form url.Values) ([]byte, int, error) {
	if endpoint == "" {
		return nil, 0, deviceErr("url_rejected")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, deviceErr("device_login_failed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, errRedirectDenied) {
			return nil, 0, deviceErr("redirect_denied")
		}
		return nil, 0, deviceErr("device_login_failed")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
	if err != nil {
		return nil, 0, deviceErr("device_login_failed")
	}
	if len(body) > 64*1024 {
		zeroBytes(body)
		return nil, 0, deviceErr("device_login_failed")
	}
	return body, resp.StatusCode, nil
}

func deviceStatusCode(status int, body []byte) string {
	if status >= 300 && status < 400 {
		return "redirect_denied"
	}
	switch status {
	case http.StatusOK:
		return ""
	case http.StatusForbidden:
		return "login_denied"
	case http.StatusTooManyRequests:
		return "slow_down"
	case http.StatusServiceUnavailable:
		return "oauth_unavailable"
	case http.StatusBadRequest:
		var payload struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return "device_login_failed"
		}
		switch payload.Error {
		case "expired_token", "slow_down", "authorization_pending":
			return payload.Error
		default:
			return "device_login_failed"
		}
	default:
		return "device_login_failed"
	}
}

func deviceSleep(ctx context.Context, deadline time.Time, interval time.Duration) error {
	if interval <= 0 {
		return nil
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return deviceErr("expired_token")
	}
	if interval > remaining {
		interval = remaining
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return deviceErr("device_login_failed")
	case <-timer.C:
		return nil
	}
}

func writeDeviceToken(path string, secret []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(secret); err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("mode")
	}
	return nil
}

func parseFlexibleDuration(raw string) (time.Duration, error) {
	if raw == "" {
		return 0, errors.New("empty")
	}
	if duration, err := time.ParseDuration(raw); err == nil {
		return duration, nil
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	return time.Duration(seconds) * time.Second, nil
}

// ParseFlexibleDuration accepts a Go duration or a bare integer number of seconds.
func ParseFlexibleDuration(raw string) (time.Duration, error) {
	return parseFlexibleDuration(raw)
}
