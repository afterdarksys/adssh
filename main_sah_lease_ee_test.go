//go:build ee

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/engine"
	"github.com/afterdarksys/adssh/internal/sah"
	"github.com/afterdarksys/adssh/security"
)

func noToken(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), "eyJ") {
		t.Fatal("token leaked")
	}
}

type sahHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
}

type sahPayload struct {
	V     int             `json:"v"`
	Iss   string          `json:"iss"`
	Kid   string          `json:"kid"`
	Sub   string          `json:"sub"`
	Host  string          `json:"host"`
	Scope string          `json:"scope"`
	Cmd   json.RawMessage `json:"cmd,omitempty"`
	Iat   int64           `json:"iat"`
	Nbf   int64           `json:"nbf"`
	Exp   int64           `json:"exp"`
	JTI   string          `json:"jti"`
}

type leaseRig struct {
	t     *testing.T
	sec   *security.Engine
	priv  ed25519.PrivateKey
	kid   string
	state string
	ran   bool
}

func newLeaseRig(t *testing.T, policy string) *leaseRig {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := "k1"
	keys := filepath.Join(t.TempDir(), "keys")
	body := "# comment\n" + kid + "=ed25519:" + base64.StdEncoding.EncodeToString(pub) + "\n"
	if err := os.WriteFile(keys, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keys, 0o600); err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	if err := os.Chmod(state, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"ADSSH_QUARANTINE", "ADSSH_QUARANTINE_FILE",
		"ADSSH_HOST_PROFILE", "ADSSH_HOST_PROFILE_PREV",
		"ADSSH_HOST_PROFILE_KEYS", "ADSSH_HOST_PROFILE_NARROW", "ADSSH_HOST_ID",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("ADSSH_SAH_REQUIRE_LEASE", "1")
	t.Setenv("ADSSH_SAH_ISSUER", "issuer")
	t.Setenv("ADSSH_SAH_HOST_ID", "host-1")
	t.Setenv("ADSSH_SAH_LEASE_KEYS", keys)
	t.Setenv("ADSSH_SAH_LEASE_STATE", state)
	eng, err := engine.New(engine.Config{
		EngineConfig: security.EngineConfig{PolicySource: []byte(policy)},
	})
	if err != nil {
		t.Fatal(err)
	}
	bindTestSession(t, eng.Security())
	r := &leaseRig{t: t, sec: eng.Security(), priv: priv, kid: kid, state: state}
	prev := sahRun
	t.Cleanup(func() { sahRun = prev })
	sahRun = func(command []string) (string, string, int, error) {
		r.ran = true
		return "ok", "", 0, nil
	}
	return r
}

func (r *leaseRig) mint(cmd []string, jti string, iat, nbf, exp int64) string {
	r.t.Helper()
	raw, err := json.Marshal(cmd)
	if err != nil {
		r.t.Fatal(err)
	}
	payload, err := json.Marshal(sahPayload{
		V: 1, Iss: "issuer", Kid: r.kid, Sub: "user:alice", Host: "host-1",
		Scope: "exec", Cmd: raw, Iat: iat, Nbf: nbf, Exp: exp, JTI: jti,
	})
	if err != nil {
		r.t.Fatal(err)
	}
	header, err := json.Marshal(sahHeader{Alg: "EdDSA", Kid: r.kid})
	if err != nil {
		r.t.Fatal(err)
	}
	h := base64.RawURLEncoding.EncodeToString(header)
	p := base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(r.priv, []byte(h+"."+p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (r *leaseRig) exec(cmd []string, lease string) (string, string, int, error) {
	r.t.Helper()
	out, errOut, code, err := sahExecute(r.sec, "sess", cmd, lease)
	noToken(r.t, err)
	return out, errOut, code, err
}

func (r *leaseRig) stateEmpty() {
	r.t.Helper()
	ents, err := os.ReadDir(r.state)
	if err != nil {
		r.t.Fatal(err)
	}
	if len(ents) != 0 {
		r.t.Fatalf("state has %d entries", len(ents))
	}
}

func (r *leaseRig) jti(suffix string) string {
	name := strings.ReplaceAll(r.t.Name(), "/", "_")
	if suffix != "" {
		name += "_" + suffix
	}
	return name
}

const (
	allowEcho = "package adssh.authz\ndefault allow = false\nallow { input.command == \"/bin/echo\" }\n"
	denyAll   = "package adssh.authz\ndefault allow = false\n"
)

func TestSAHHandoffStaysNotWired(t *testing.T) {
	if sah.Handoff != "not_wired" {
		t.Fatalf("handoff %q", sah.Handoff)
	}
}

func TestSAHLeaseHappyAndReplay(t *testing.T) {
	r := newLeaseRig(t, allowEcho)
	now := time.Now().UTC()
	tok := r.mint([]string{"/bin/echo", "hi"}, r.jti(""), now.Unix(), now.Unix(), now.Unix()+60)
	out, _, code, err := r.exec([]string{"/bin/echo", "hi"}, tok)
	if err != nil || code != 0 || out != "ok" || !r.ran {
		t.Fatalf("happy code %d err %v out %q ran %v", code, err, out, r.ran)
	}
	r.ran = false
	_, _, _, err = r.exec([]string{"/bin/echo", "hi"}, tok)
	noToken(t, err)
	if err == nil || err.Error() != "lease_replayed" || r.ran {
		t.Fatalf("replay: %v ran %v", err, r.ran)
	}

	deny := newLeaseRig(t, denyAll)
	now = time.Now().UTC()
	tok = deny.mint([]string{"/bin/echo", "hi"}, deny.jti("d"), now.Unix(), now.Unix(), now.Unix()+60)
	_, _, _, err = deny.exec([]string{"/bin/echo", "hi"}, tok)
	if err == nil || err.Error() != "adssh: access denied for '/bin/echo' by policy" || deny.ran {
		t.Fatalf("deny: %v", err)
	}
	_, _, _, err = deny.exec([]string{"/bin/echo", "hi"}, tok)
	if err == nil || err.Error() != "lease_replayed" {
		t.Fatalf("deny replay: %v", err)
	}
}

func TestSAHLeaseNegatives(t *testing.T) {
	r := newLeaseRig(t, allowEcho)
	now := time.Now().UTC()
	_, _, _, err := r.exec([]string{"/bin/echo", "hi"}, "")
	if err == nil || err.Error() != "lease_required" || r.ran {
		t.Fatalf("empty: %v", err)
	}
	r.stateEmpty()

	tok := r.mint([]string{"/bin/echo", "hi"}, r.jti("mis"), now.Unix(), now.Unix(), now.Unix()+60)
	_, _, _, err = r.exec([]string{"/bin/echo", "no"}, tok)
	if err == nil || err.Error() != "lease_command_mismatch" || r.ran {
		t.Fatalf("mismatch: %v", err)
	}
	r.stateEmpty()

	exp := r.mint([]string{"/bin/echo", "hi"}, r.jti("old"), now.Unix()-120, now.Unix()-120, now.Unix()-30)
	_, _, _, err = r.exec([]string{"/bin/echo", "hi"}, exp)
	if err == nil || err.Error() != "lease_expired" || r.ran {
		t.Fatalf("expired: %v", err)
	}
	r.stateEmpty()

	_, _, _, err = r.exec([]string{"/bin/echo", "hi"}, " ")
	if err == nil || err.Error() != "lease_rejected" {
		t.Fatalf("space: %v", err)
	}
	_, _, _, err = r.exec([]string{"/bin/echo", "hi"}, strings.Repeat("a", 9*1024))
	if err == nil || err.Error() != "lease_rejected" {
		t.Fatalf("oversize: %v", err)
	}
	r.stateEmpty()

	off := newLeaseRig(t, denyAll)
	off.t.Setenv("ADSSH_SAH_REQUIRE_LEASE", "")
	_, _, _, err = off.exec([]string{"/bin/echo", "hi"}, "not-a-lease")
	if err == nil || err.Error() != "policy_denied" || off.ran {
		t.Fatalf("require off: %v ran %v", err, off.ran)
	}
}

func TestSAHLeaseAuditFailureDoesNotCommit(t *testing.T) {
	r := newLeaseRig(t, allowEcho)
	ledger := t.TempDir()
	key := filepath.Join(t.TempDir(), "key")
	if err := r.sec.InitChain(ledger, key, "sess"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tok := r.mint([]string{"/bin/echo", "hi"}, r.jti(""), now.Unix(), now.Unix(), now.Unix()+60)
	_, _, _, err := r.exec([]string{"/bin/echo", "hi"}, tok)
	if err == nil || err.Error() != "execute_failed" || r.ran {
		t.Fatalf("first: %v", err)
	}
	r.stateEmpty()
	_, _, _, err = r.exec([]string{"/bin/echo", "hi"}, tok)
	if err == nil || err.Error() != "execute_failed" || r.ran {
		t.Fatalf("second: %v", err)
	}
	r.stateEmpty()
}
