//go:build ee

package security

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
)

const hostUsage = "host: usage: host <drift|status|verify|commit|rollback> [FILE]"

func newSigner(t *testing.T, kid string) testSigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testSigner{Kid: kid, Priv: priv}
}

func writeHostKeys(t *testing.T, signers ...testSigner) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("# comment\n")
	for _, s := range signers {
		pub := s.Priv.Public().(ed25519.PublicKey)
		b.WriteString(s.Kid + "=ed25519:" + base64.StdEncoding.EncodeToString(pub) + "\n")
	}
	path := filepath.Join(t.TempDir(), "keys")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func sampleProfile(users []string, policy, admin string) hostProfile {
	if users == nil {
		users = []string{"alice"}
	}
	if policy == "" {
		policy = "abc"
	}
	if admin == "" {
		admin = "def"
	}
	return hostProfile{
		V: 1, Host: "host-1",
		Users: users, Listeners: []string{}, Packages: []string{},
		Sysctls: []string{}, Units: []string{"nginx.service"},
		PolicyHash: policy, AdminKeysHash: admin,
	}
}

func signProfile(t *testing.T, p hostProfile, signers ...testSigner) []byte {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	body, err := signEnvelope(signers, raw)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func writeBytes(t *testing.T, dir, name string, body []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func armHost(t *testing.T) (*Engine, context.Context, string, string, string, string, testSigner, testSigner) {
	t.Helper()
	eng, ctx, sid := adminFix(t)
	dir := t.TempDir()
	k1 := newSigner(t, "k1")
	k2 := newSigner(t, "k2")
	t.Setenv("ADSSH_HOST_PROFILE", filepath.Join(dir, "profile"))
	t.Setenv("ADSSH_HOST_PROFILE_PREV", filepath.Join(dir, "prev"))
	t.Setenv("ADSSH_HOST_PROFILE_KEYS", writeHostKeys(t, k1, k2))
	t.Setenv("ADSSH_HOST_ID", "host-1")
	return eng, ctx, sid, dir, filepath.Join(dir, "profile"), filepath.Join(dir, "prev"), k1, k2
}

func mustNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("path exists or unreadable: %v", err)
	}
}

func TestHostUsageSessionAndAgent(t *testing.T) {
	_, ctx, sid := adminFix(t)
	if err := (hostBinary{}).Run(context.Background(), []string{"host", "--help"}); err != nil {
		t.Fatal(err)
	}
	equalErr(t, (hostBinary{}).Run(ctx, []string{"host", "drift", "extra"}), hostUsage)
	equalErr(t, (hostBinary{}).Run(ctx, []string{"host", "commit"}), hostUsage)
	equalErr(t, (hostBinary{}).Run(context.Background(), []string{"host", "commit", "f"}), "host: requires a session")

	sys.GetSession(sid).BindManagedAgent(&sys.ManagedAgent{ID: "agent-1", ExpiresAt: time.Now().Add(time.Hour)})
	equalErr(t, (hostBinary{}).Run(ctx, []string{"host", "commit", "nope"}), "host: agents cannot run host")

	sys.UnregisterSession(sid)
	_, ctx, _ = adminFix(t)
	t.Setenv("ADSSH_QUARANTINE", "1")
	equalErr(t, (hostBinary{}).Run(context.Background(), []string{"host", "commit", "f"}), "host: requires a session")
	equalErr(t, (hostBinary{}).Run(ctx, []string{"host", "commit", "f"}), "host: refused")
	equalErr(t, (hostBinary{}).Run(WithRecover(ctx), []string{"host", "rollback"}), "host: refused")
}

func TestHostCommitRejectsBadProfiles(t *testing.T) {
	eng, ctx, _, dir, inst, _, k1, _ := armHost(t)
	_ = eng
	good := signProfile(t, sampleProfile(nil, "", ""), k1)

	t.Setenv("ADSSH_HOST_ID", "")
	equalErr(t, (hostBinary{}).Run(ctx, []string{"host", "commit", writeBytes(t, dir, "empty-id", good)}), "host: profile_rejected")
	mustNotExist(t, inst)

	t.Setenv("ADSSH_HOST_ID", "other")
	equalErr(t, (hostBinary{}).Run(ctx, []string{"host", "commit", writeBytes(t, dir, "mismatch", good)}), "host: profile_rejected")
	mustNotExist(t, inst)

	t.Setenv("ADSSH_HOST_ID", "host-1")
	tampered := tamperHostSig(t, good)
	equalErr(t, (hostBinary{}).Run(ctx, []string{"host", "commit", writeBytes(t, dir, "tamper", tampered)}), "host: profile_rejected")
	mustNotExist(t, inst)

	real := writeBytes(t, dir, "real", good)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	equalErr(t, (hostBinary{}).Run(ctx, []string{"host", "commit", link}), "host: profile_rejected")
	mustNotExist(t, inst)

	raw, err := json.Marshal(sampleProfile(nil, "", ""))
	if err != nil {
		t.Fatal(err)
	}
	equalErr(t, (hostBinary{}).Run(ctx, []string{"host", "commit", writeBytes(t, dir, "unsigned", raw)}), "host: profile_widen")
	mustNotExist(t, inst)
}

func tamperHostSig(t *testing.T, body []byte) []byte {
	t.Helper()
	var env signedEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(env.Sigs[0].Sig)
	if err != nil || len(raw) == 0 {
		t.Fatal(err)
	}
	raw[0] ^= 0x01
	env.Sigs[0].Sig = base64.StdEncoding.EncodeToString(raw)
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestHostCommitWidenAndChmod(t *testing.T) {
	eng, ctx, sid, dir, inst, prev, k1, k2 := armHost(t)
	first := signProfile(t, sampleProfile(nil, "abc", "def"), k1)
	if err := (hostBinary{}).Run(ctx, []string{"host", "commit", writeBytes(t, dir, "first", first)}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(inst)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	if _, err := readOwnerOnly(inst, envelopeBytesMax); err != nil {
		t.Fatal(err)
	}

	widened := signProfile(t, sampleProfile(nil, "xyz", "def"), k1)
	deny := denyEngine(t)
	equalErr(t, (hostBinary{}).Run(planeCtx(deny, sid), []string{"host", "commit", writeBytes(t, dir, "wide", widened)}), "host: profile_widen")
	got, err := os.ReadFile(inst)
	if err != nil || !bytes.Equal(got, first) {
		t.Fatalf("installed changed: %v", err)
	}
	mustNotExist(t, prev)

	both := signProfile(t, sampleProfile(nil, "xyz", "def"), k1, k2)
	if err := (hostBinary{}).Run(ctx, []string{"host", "commit", writeBytes(t, dir, "both", both)}); err != nil {
		t.Fatal(err)
	}
	prevBody, err := os.ReadFile(prev)
	if err != nil || !bytes.Equal(prevBody, first) {
		t.Fatal("prev is not the first envelope")
	}
	instBody, err := os.ReadFile(inst)
	if err != nil || !bytes.Equal(instBody, both) {
		t.Fatal("installed is not the widened envelope")
	}

	// Same hashes, one signer, user list grows. chmod fails after the rename.
	if err := os.Rename(prev, inst); err != nil {
		t.Fatal(err)
	}
	os.Remove(prev)
	grown := signProfile(t, sampleProfile([]string{"alice", "carol"}, "abc", "def"), k1)
	hostChmod = func(string, os.FileMode) error { return errors.New("chmod failed") }
	err = (hostBinary{}).Run(ctx, []string{"host", "commit", writeBytes(t, dir, "grown", grown)})
	var ce chmodError
	if !errors.As(err, &ce) || err.Error() != "chmod failed" {
		t.Fatalf("chmod: %v", err)
	}
	mustNotExist(t, inst)
	kept, err := os.ReadFile(prev)
	if err != nil || !bytes.Equal(kept, first) {
		t.Fatal("prev lost the previous profile")
	}
	_ = eng
}

func TestHostDriftVerifyAndRollback(t *testing.T) {
	eng, ctx, sid, dir, inst, prev, k1, _ := armHost(t)
	first := signProfile(t, sampleProfile(nil, "", ""), k1)
	narrowRaw, err := json.Marshal(sampleProfile(nil, "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inst+".narrow", narrowRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	equalErr(t, (hostBinary{}).Run(ctx, []string{"host", "drift"}), "host: profile_widen")

	t.Setenv("ADSSH_HOST_PROFILE_NARROW", filepath.Join(dir, "missing-narrow"))
	equalErr(t, (hostBinary{}).Run(ctx, []string{"host", "drift"}), "host: profile_rejected")

	signedNarrow := signProfile(t, sampleProfile(nil, "", ""), k1)
	t.Setenv("ADSSH_HOST_PROFILE_NARROW", writeBytes(t, dir, "signed.narrow", signedNarrow))
	equalErr(t, (hostBinary{}).Run(ctx, []string{"host", "drift"}), "host: profile_rejected")

	t.Setenv("ADSSH_HOST_PROFILE_NARROW", filepath.Join(dir, "absent-narrow"))
	if err := (hostBinary{}).Run(ctx, []string{"host", "commit", writeBytes(t, dir, "first", first)}); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"drift", "status"} {
		out, err := runVBin(t, eng, sid, []string{"host", sub})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, "host=host-1\n") || !strings.Contains(out, "users=alice\n") {
			t.Fatalf("%s output:\n%s", sub, out)
		}
	}
	out, err := runVBin(t, eng, sid, []string{"host", "verify"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "host=host-1\n") || !strings.HasSuffix(out, "host: verified\n") {
		t.Fatalf("verify:\n%s", out)
	}

	carol := signProfile(t, sampleProfile([]string{"carol"}, "", ""), k1)
	writeBytes(t, dir, "prev", carol)
	if err := (hostBinary{}).Run(ctx, []string{"host", "rollback"}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(inst)
	if err != nil || !bytes.Equal(got, carol) {
		t.Fatal("rollback did not install the previous profile")
	}
	_ = prev
}
