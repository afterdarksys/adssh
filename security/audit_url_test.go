package security

// Threats: ADSSH_AUDIT_URL is checked for syntax only when the engine is
// built, so DNS that is down or slow cannot stop adssh from starting (a login
// shell lockout). The address check moves to the POST: an unresolved host or a
// private answer fails that one POST closed with an error that names the
// cause, and the bearer is never sent.

import (
	"bytes"
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func stubCallbackLookup(t *testing.T, fn func(ctx context.Context, host string) ([]net.IP, error)) {
	t.Helper()
	orig := callbackLookupIP
	callbackLookupIP = fn
	t.Cleanup(func() { callbackLookupIP = orig })
}

func TestAuditURLConstructionDoesNoLookup(t *testing.T) {
	stubCallbackLookup(t, func(context.Context, string) ([]net.IP, error) {
		t.Error("engine construction resolved the audit host")
		return nil, errors.New("no network")
	})
	eng, err := NewEngine(EngineConfig{
		AuditLogPath:  filepath.Join(t.TempDir(), "audit.log"),
		AuditLogURL:   "https://siem.invalid/hook",
		AuditLogToken: "bearer-xyz",
	})
	if err != nil {
		t.Fatalf("construction with unresolvable host: %v", err)
	}
	if eng.remoteAuditURL != "https://siem.invalid/hook" {
		t.Fatalf("remote url %q", eng.remoteAuditURL)
	}
}

func TestAuditURLConstructionRejectsBadSyntax(t *testing.T) {
	t.Setenv("ADSSH_CALLBACK_ALLOW_PRIVATE", "")
	stubCallbackLookup(t, func(context.Context, string) ([]net.IP, error) {
		t.Error("syntax check resolved a host")
		return nil, errors.New("no network")
	})
	dir := t.TempDir()
	for _, raw := range []string{
		"http://siem.example/hook",
		"https://user:pw@siem.example/hook",
		"https://siem.example/hook#frag",
		"https:///hook",
		"https://localhost/hook",
		"https://169.254.169.254/x",
		"https://[fe80::1]/x",
	} {
		_, err := NewEngine(EngineConfig{AuditLogPath: filepath.Join(dir, "audit.log"), AuditLogURL: raw, AuditLogToken: "bearer-xyz"})
		if err == nil || !strings.Contains(err.Error(), "audit webhook URL rejected") {
			t.Fatalf("%s: %v", raw, err)
		}
		if strings.Contains(err.Error(), "bearer-xyz") {
			t.Fatal("error leaked token")
		}
	}
	_, err := NewEngine(EngineConfig{AuditLogPath: filepath.Join(dir, "audit.log"), AuditLogURL: "https://10.0.0.8/hook"})
	if err == nil || !strings.Contains(err.Error(), "ADSSH_AUDIT_URL: host 10.0.0.8 resolves to a private address; set ADSSH_CALLBACK_ALLOW_PRIVATE=1 to allow it") {
		t.Fatalf("private literal: %v", err)
	}
	t.Setenv("ADSSH_CALLBACK_ALLOW_PRIVATE", "1")
	if _, err := NewEngine(EngineConfig{AuditLogPath: filepath.Join(dir, "audit.log"), AuditLogURL: "https://10.0.0.8/hook"}); err != nil {
		t.Fatalf("private literal with override: %v", err)
	}
}

func TestAuditPostUnresolvedHostFailsClosed(t *testing.T) {
	stubCallbackLookup(t, func(context.Context, string) ([]net.IP, error) {
		return nil, errors.New("server misbehaving")
	})
	err := postAuditEvent(context.Background(), "https://siem.invalid/hook", "bearer-xyz", []byte(`{}`))
	if err == nil {
		t.Fatal("POST to unresolved host succeeded")
	}
	want := "ADSSH_AUDIT_URL: host siem.invalid did not resolve: server misbehaving"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q, want %q", err, want)
	}
	if strings.Contains(err.Error(), "bearer-xyz") {
		t.Fatal("error leaked token")
	}
}

func TestAuditPostResolveIsBounded(t *testing.T) {
	stubCallbackLookup(t, func(ctx context.Context, _ string) ([]net.IP, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	orig := auditResolveTimeout
	auditResolveTimeout = 50 * time.Millisecond
	t.Cleanup(func() { auditResolveTimeout = orig })
	start := time.Now()
	err := postAuditEvent(context.Background(), "https://siem.invalid/hook", "", []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), "did not resolve") {
		t.Fatalf("slow DNS: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("resolve not bounded: %v", time.Since(start))
	}
}

func TestAuditPostPrivateHostNeedsOverride(t *testing.T) {
	stubCallbackLookup(t, func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.255.255.1")}, nil
	})
	want := "ADSSH_AUDIT_URL: host siem.corp resolves to a private address; set ADSSH_CALLBACK_ALLOW_PRIVATE=1 to allow it"

	t.Setenv("ADSSH_CALLBACK_ALLOW_PRIVATE", "")
	err := postAuditEvent(context.Background(), "https://siem.corp/hook", "bearer-xyz", []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("private without override: %v", err)
	}

	t.Setenv("ADSSH_CALLBACK_ALLOW_PRIVATE", "1")
	if _, err := auditResolveHost(context.Background(), "siem.corp"); err != nil {
		t.Fatalf("private with override: %v", err)
	}
	// With the override the POST gets past the address check and fails only
	// because nothing answers at the test address.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err = postAuditEvent(ctx, "https://siem.corp/hook", "bearer-xyz", []byte(`{}`))
	if err == nil {
		t.Fatal("POST to an unanswered address succeeded")
	}
	if strings.Contains(err.Error(), "private address") || strings.Contains(err.Error(), "did not resolve") {
		t.Fatalf("override not honoured: %v", err)
	}
}

func TestAuditPostMetadataHostRefusedEvenWithOverride(t *testing.T) {
	t.Setenv("ADSSH_CALLBACK_ALLOW_PRIVATE", "1")
	stubCallbackLookup(t, func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("169.254.169.254")}, nil
	})
	err := postAuditEvent(context.Background(), "https://siem.corp/hook", "", []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), "ADSSH_AUDIT_URL: host siem.corp resolves to a blocked address") {
		t.Fatalf("metadata answer: %v", err)
	}
}

func TestAuditWarnRateLimited(t *testing.T) {
	var buf bytes.Buffer
	origW, origLast := auditWarnWriter, auditWarnLast.Load()
	auditWarnWriter = &buf
	auditWarnLast.Store(0)
	t.Cleanup(func() {
		auditWarnWriter = origW
		auditWarnLast.Store(origLast)
	})
	auditWarn("siem.invalid", errors.New("first"))
	auditWarn("siem.invalid", errors.New("second"))
	out := buf.String()
	if strings.Count(out, "\n") != 1 || !strings.Contains(out, "first") || strings.Contains(out, "second") {
		t.Fatalf("warn output %q", out)
	}
}
