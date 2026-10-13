package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
)

func TestDeviceLoginStoresBearerAndSetsUser(t *testing.T) {
	const access = "opaque-access-token-value"
	const deviceCode = "device-code-secret"
	var base string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			t.Errorf("content-type %q", ct)
			http.Error(w, "bad type", http.StatusBadRequest)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/device":
			if r.Form.Get("username") != "alice" {
				t.Errorf("username %q", r.Form.Get("username"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code":      deviceCode,
				"verification_url": base + "/oauth/device/verify?code=user-code",
				"expires_in":       600,
				"interval":         5,
			})
		case "/oauth/token":
			if r.Form.Get("grant_type") != deviceGrantType || r.Form.Get("device_code") != deviceCode {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": access,
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	base = server.URL

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "device.token")
	auditPath := filepath.Join(dir, "audit.log")
	engine, err := NewEngine(EngineConfig{AuditLogPath: auditPath})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	sessionID := "device-login-happy"
	sys.RegisterSession(&sys.Session{ID: sessionID, User: "bob", Principals: []string{"ops"}})
	t.Cleanup(func() { sys.UnregisterSession(sessionID) })
	ctx := WithSessionID(context.WithValue(context.Background(), engineCtxKey, engine), sessionID)

	result, err := DeviceLogin(ctx, DeviceLoginRequest{
		URL:       server.URL + "/ignored?leak=1#frag",
		Username:  "alice",
		TokenFile: tokenPath,
		Timeout:   time.Second,
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if result.TokenFile != tokenPath {
		t.Fatalf("token file %q", result.TokenFile)
	}
	sum := sha256.Sum256([]byte(access))
	wantFP := hex.EncodeToString(sum[:])
	if result.Fingerprint != wantFP {
		t.Fatalf("fingerprint %s", result.Fingerprint)
	}
	if strings.Contains(fmt.Sprintf("%+v", result), access) || strings.Contains(fmt.Sprintf("%+v", result), deviceCode) {
		t.Fatal("result carried a secret")
	}
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	stored, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != access {
		t.Fatal("token file mismatch")
	}
	session := sys.GetSession(sessionID)
	got := session.Info()
	if got.User != "alice" || len(got.Principals) != 0 {
		t.Fatalf("identity user=%q principals=%v", got.User, got.Principals)
	}
	audit, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(audit)
	if !strings.Contains(text, "IDENTITY_DEVICE_LOGIN user=alice fingerprint="+wantFP) {
		t.Fatalf("audit %q", text)
	}
	if strings.Contains(text, access) || strings.Contains(text, deviceCode) {
		t.Fatal("audit contained a secret")
	}
}

func TestDeviceLoginRejectsUnsafeURLsWithoutDial(t *testing.T) {
	sessionID := "device-login-urls"
	sys.RegisterSession(&sys.Session{ID: sessionID, User: "alice"})
	t.Cleanup(func() { sys.UnregisterSession(sessionID) })
	ctx := WithSessionID(context.Background(), sessionID)
	tokenPath := filepath.Join(t.TempDir(), "device.token")
	for _, raw := range []string{
		"http://example.com/oauth",
		"http://localhost/oauth",
		"http://169.254.169.254/latest",
		"https://metadata.google.internal/computeMetadata/v1/",
	} {
		_, err := DeviceLogin(ctx, DeviceLoginRequest{
			URL:       raw,
			Username:  "alice",
			TokenFile: tokenPath,
			Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatalf("dialed %s", raw)
				return nil, nil
			})},
		})
		if err == nil || err.Error() != "url_rejected" {
			t.Fatalf("%s: %v", raw, err)
		}
	}
}

func TestDeviceLoginMapsPollAndRedirectFailures(t *testing.T) {
	cases := []struct {
		name string
		hook func(w http.ResponseWriter, r *http.Request, base string)
		want string
	}{
		{
			name: "redirect",
			hook: func(w http.ResponseWriter, r *http.Request, base string) {
				http.Redirect(w, r, base+"/other", http.StatusFound)
			},
			want: "redirect_denied",
		},
		{
			name: "expired",
			hook: func(w http.ResponseWriter, r *http.Request, base string) {
				if r.URL.Path == "/oauth/token" {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": "expired_token"})
					return
				}
				writeDeviceStart(w, base)
			},
			want: "expired_token",
		},
		{
			name: "origin",
			hook: func(w http.ResponseWriter, r *http.Request, base string) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"device_code":      "dev",
					"verification_url": "https://127.0.0.1/oauth/device/verify?code=abc",
					"expires_in":       600,
					"interval":         0,
				})
			},
			want: "url_rejected",
		},
		{
			name: "token-type",
			hook: func(w http.ResponseWriter, r *http.Request, base string) {
				if r.URL.Path == "/oauth/token" {
					_ = json.NewEncoder(w).Encode(map[string]any{
						"access_token": "not-bearer-secret",
						"token_type":   "bearer",
						"expires_in":   3600,
					})
					return
				}
				writeDeviceStart(w, base)
			},
			want: "device_login_failed",
		},
		{
			name: "query-key",
			hook: func(w http.ResponseWriter, r *http.Request, base string) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"device_code":      "dev",
					"verification_url": base + "/oauth/device/verify?device_code=secret",
					"expires_in":       600,
				})
			},
			want: "url_rejected",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var base string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil && r.URL.Path != "" {
					t.Errorf("form: %v", err)
				}
				tc.hook(w, r, base)
			}))
			defer server.Close()
			base = server.URL
			sessionID := "device-login-" + tc.name
			sys.RegisterSession(&sys.Session{ID: sessionID, User: "alice"})
			t.Cleanup(func() { sys.UnregisterSession(sessionID) })
			ctx := WithSessionID(context.Background(), sessionID)
			tokenPath := filepath.Join(t.TempDir(), "device.token")
			_, err := DeviceLogin(ctx, DeviceLoginRequest{
				URL:       server.URL,
				Username:  "alice",
				TokenFile: tokenPath,
				Timeout:   time.Second,
			})
			if err == nil || err.Error() != tc.want {
				t.Fatalf("got %v want %s", err, tc.want)
			}
			if _, statErr := os.Stat(tokenPath); !os.IsNotExist(statErr) {
				t.Fatalf("token file created: %v", statErr)
			}
		})
	}
}

func TestDeviceLoginIntervalZeroDoesNotSleep(t *testing.T) {
	var polls int
	var base string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.URL.Path == "/oauth/device" {
			writeDeviceStart(w, base)
			return
		}
		polls++
		if polls == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "slow_down"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "interval-secret",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()
	base = server.URL
	sessionID := "device-login-interval"
	sys.RegisterSession(&sys.Session{ID: sessionID, User: "bob"})
	t.Cleanup(func() { sys.UnregisterSession(sessionID) })
	ctx := WithSessionID(context.Background(), sessionID)
	start := time.Now()
	result, err := DeviceLogin(ctx, DeviceLoginRequest{
		URL:         server.URL,
		Username:    "alice",
		TokenFile:   filepath.Join(t.TempDir(), "device.token"),
		Interval:    0,
		IntervalSet: true,
		Timeout:     time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("slept %s", time.Since(start))
	}
	if result.Fingerprint != fingerprintSecret("interval-secret") {
		t.Fatal(result.Fingerprint)
	}
}

func TestDeviceLoginRejectsRelativePathAndMissingSession(t *testing.T) {
	_, err := DeviceLogin(context.Background(), DeviceLoginRequest{URL: "https://127.0.0.1", Username: "alice"})
	if err == nil || err.Error() != "identity: requires an active registered session" {
		t.Fatalf("session: %v", err)
	}
	sessionID := "device-login-relative"
	sys.RegisterSession(&sys.Session{ID: sessionID, User: "alice"})
	t.Cleanup(func() { sys.UnregisterSession(sessionID) })
	ctx := WithSessionID(context.Background(), sessionID)
	_, err = DeviceLogin(ctx, DeviceLoginRequest{
		URL:       "https://127.0.0.1",
		Username:  "alice",
		TokenFile: "relative.token",
		Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("dialed relative path")
			return nil, nil
		})},
	})
	if err == nil || err.Error() != "token_file_rejected" {
		t.Fatalf("path: %v", err)
	}
	_, err = DeviceLogin(ctx, DeviceLoginRequest{URL: "https://127.0.0.1", Username: "bad name"})
	if err == nil || err.Error() != "login_denied" {
		t.Fatalf("username: %v", err)
	}
}

func TestParseFlexibleDurationBareSeconds(t *testing.T) {
	got, err := parseFlexibleDuration("0")
	if err != nil || got != 0 {
		t.Fatalf("0: %v %s", err, got)
	}
	got, err = parseFlexibleDuration("5s")
	if err != nil || got != 5*time.Second {
		t.Fatalf("5s: %v %s", err, got)
	}
}

func writeDeviceStart(w http.ResponseWriter, base string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"device_code":      "dev",
		"verification_url": base + "/oauth/device/verify?code=user",
		"expires_in":       600,
		"interval":         5,
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestValidateCallbackURLAllowsLiteralLoopbackOnly(t *testing.T) {
	if _, err := validateCallbackURL("http://127.0.0.1:9/oauth"); err != nil {
		t.Fatal(err)
	}
	if _, err := validateCallbackURL("http://[::1]:9/oauth"); err != nil {
		t.Fatal(err)
	}
	if _, err := validateCallbackURL("https://127.0.0.2/oauth"); err == nil {
		t.Fatal("other loopback accepted")
	}
	parsed, err := url.Parse("https://user:secret@127.0.0.1/oauth")
	if err != nil || parsed.User == nil {
		t.Fatal("fixture")
	}
	if _, err := validateCallbackURL(parsed.String()); err == nil {
		t.Fatal("userinfo accepted")
	}
}
