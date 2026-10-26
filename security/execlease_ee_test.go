//go:build ee

package security

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
)

func writeKeyLine(t *testing.T, kid string, pub ed25519.PublicKey, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "keys")
	body := "# comment\n\n" + kid + "=ed25519:" + base64.StdEncoding.EncodeToString(pub) + "\n"
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustCmd(t *testing.T, args ...string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type leaseFix struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	opt  LeaseOptions
	body leasePayload
	now  time.Time
}

func newLeaseFix(t *testing.T, mode os.FileMode) leaseFix {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	path := writeKeyLine(t, "hub-1", pub, mode)
	body := leasePayload{
		V: 1, Iss: "hub", Kid: "hub-1", Sub: "user:alice", Host: "host-1",
		Scope: "exec", Cmd: mustCmd(t, "/bin/echo", "hi"),
		Iat: now.Unix(), Nbf: now.Unix(), Exp: now.Unix() + 60, JTI: "jti-1",
	}
	opt := LeaseOptions{
		KeysFile: path, Issuer: "hub", HostID: "host-1", Scope: "exec",
		Command: []string{"/bin/echo", "hi"}, Now: now,
	}
	return leaseFix{pub: pub, priv: priv, opt: opt, body: body, now: now}
}

func (f leaseFix) token() string {
	return signTestLease(f.priv, f.body.Kid, "", f.body)
}

func TestVerifyExecLeaseAcceptsPinnedEd25519(t *testing.T) {
	f := newLeaseFix(t, 0o600)
	got, err := VerifyExecLease(f.token(), f.opt)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sub != "user:alice" || got.JTI != "jti-1" || got.Kid != "hub-1" {
		t.Fatalf("claim = %+v", got)
	}
	if _, err := VerifyExecLease(f.token(), f.opt); err != nil {
		t.Fatal("verify must not consume the jti")
	}
	fp := LeaseFingerprint(f.token())
	if strings.Contains(fp, f.token()) || len(fp) != 64 {
		t.Fatalf("fingerprint %q", fp)
	}
}

func TestVerifyExecLeaseOwnerOnlyModes(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o400} {
		f := newLeaseFix(t, mode)
		if _, err := VerifyExecLease(f.token(), f.opt); err != nil {
			t.Fatalf("mode %o: %v", mode, err)
		}
	}
}

func TestVerifyExecLeaseRejects(t *testing.T) {
	f := newLeaseFix(t, 0o600)
	good := f.token()
	cases := []struct {
		name string
		tok  string
		opt  LeaseOptions
		want error
	}{
		{name: "empty", tok: "", opt: f.opt, want: errLeaseRejected},
		{name: "whitespace", tok: good + "\n", opt: f.opt, want: errLeaseRejected},
		{name: "two segments", tok: "a.b", opt: f.opt, want: errLeaseRejected},
		{name: "four segments", tok: good + ".x", opt: f.opt, want: errLeaseRejected},
		{name: "empty segment", tok: "a..c", opt: f.opt, want: errLeaseRejected},
		{name: "oversized", tok: strings.Repeat("a", leaseTokenMax+1), opt: f.opt, want: errLeaseRejected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyExecLease(tc.tok, tc.opt)
			if err != tc.want {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}

	if _, err := VerifyExecLease(tamperSig(t, good), f.opt); err != errLeaseRejected {
		t.Fatalf("tampered: %v", err)
	}

	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong := f.opt
	wrong.KeysFile = writeKeyLine(t, "hub-1", other, 0o600)
	if _, err := VerifyExecLease(good, wrong); err != errLeaseRejected {
		t.Fatalf("wrong key: %v", err)
	}

	loose := f.opt
	loose.KeysFile = writeKeyLine(t, "hub-1", f.pub, 0o644)
	if _, err := VerifyExecLease(good, loose); err != errLeaseRejected {
		t.Fatalf("0644: %v", err)
	}

	link := filepath.Join(t.TempDir(), "keys-link")
	if err := os.Symlink(f.opt.KeysFile, link); err != nil {
		t.Fatal(err)
	}
	linked := f.opt
	linked.KeysFile = link
	if _, err := VerifyExecLease(good, linked); err != errLeaseRejected {
		t.Fatalf("symlink keys: %v", err)
	}

	dup := filepath.Join(t.TempDir(), "dup")
	line := "hub-1=ed25519:" + base64.StdEncoding.EncodeToString(f.pub)
	if err := os.WriteFile(dup, []byte(line+"\n"+line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dupOpt := f.opt
	dupOpt.KeysFile = dup
	if _, err := VerifyExecLease(good, dupOpt); err != errLeaseRejected {
		t.Fatalf("duplicate kid: %v", err)
	}
}

func tamperSig(t *testing.T, tok string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 0xff
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	return strings.Join(parts, ".")
}

func TestVerifyExecLeaseAlgIgnoredWhenSignatureHolds(t *testing.T) {
	f := newLeaseFix(t, 0o600)
	for _, alg := range []string{"none", "HS256", "EdDSA"} {
		tok := signTestLease(f.priv, "hub-1", alg, f.body)
		if _, err := VerifyExecLease(tok, f.opt); err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if _, err := VerifyExecLease(tamperSig(t, tok), f.opt); err != errLeaseRejected {
			t.Fatalf("%s bad sig: %v", alg, err)
		}
	}
}

func TestVerifyExecLeaseTimeAndCommand(t *testing.T) {
	f := newLeaseFix(t, 0o600)

	expired := f.body
	expired.Iat = f.now.Unix() - 120
	expired.Nbf = expired.Iat
	expired.Exp = f.now.Unix() - 1
	if _, err := VerifyExecLease(signTestLease(f.priv, "hub-1", "", expired), f.opt); err != errLeaseExpired {
		t.Fatalf("expired: %v", err)
	}
	mismatch := f.opt
	mismatch.Command = []string{"/bin/echo", "no"}
	if _, err := VerifyExecLease(signTestLease(f.priv, "hub-1", "", expired), mismatch); err != errLeaseExpired {
		t.Fatalf("expired mismatch: %v", err)
	}

	if _, err := VerifyExecLease(tamperSig(t, signTestLease(f.priv, "hub-1", "", expired)), f.opt); err != errLeaseRejected {
		t.Fatalf("bad sig expired: %v", err)
	}

	futureIat := f.body
	futureIat.Iat = f.now.Unix() + 10
	futureIat.Nbf = futureIat.Iat
	futureIat.Exp = futureIat.Iat + 60
	if _, err := VerifyExecLease(signTestLease(f.priv, "hub-1", "", futureIat), f.opt); err != errLeaseRejected {
		t.Fatalf("future iat: %v", err)
	}

	futureNbf := f.body
	futureNbf.Nbf = f.now.Unix() + 30
	futureNbf.Exp = futureNbf.Nbf + 30
	if _, err := VerifyExecLease(signTestLease(f.priv, "hub-1", "", futureNbf), f.opt); err != errLeaseRejected {
		t.Fatalf("future nbf: %v", err)
	}

	wide := f.body
	wide.Exp = f.body.Iat + leaseWindowMax + 1
	if _, err := VerifyExecLease(signTestLease(f.priv, "hub-1", "", wide), f.opt); err != errLeaseRejected {
		t.Fatalf("window: %v", err)
	}
	edge := f.body
	edge.Exp = f.body.Iat + leaseWindowMax
	if _, err := VerifyExecLease(signTestLease(f.priv, "hub-1", "", edge), f.opt); err != nil {
		t.Fatalf("window edge: %v", err)
	}

	wrong := f.opt
	wrong.Command = []string{"/bin/true"}
	if _, err := VerifyExecLease(f.token(), wrong); err != errLeaseCommandMismatch {
		t.Fatalf("mismatch: %v", err)
	}

	prefixed := f.body
	prefixed.CmdPrefix = json.RawMessage(`[]`)
	if _, err := VerifyExecLease(signTestLease(f.priv, "hub-1", "", prefixed), f.opt); err != errLeaseRejected {
		t.Fatalf("cmd_prefix: %v", err)
	}
	prefixed.Exp = f.now.Unix() - 1
	prefixed.Iat = prefixed.Exp - 10
	prefixed.Nbf = prefixed.Iat
	if _, err := VerifyExecLease(signTestLease(f.priv, "hub-1", "", prefixed), f.opt); err != errLeaseRejected {
		t.Fatalf("expired cmd_prefix: %v", err)
	}

	nullPrefix := f.body
	nullPrefix.CmdPrefix = json.RawMessage(`null`)
	if _, err := VerifyExecLease(signTestLease(f.priv, "hub-1", "", nullPrefix), f.opt); err != errLeaseRejected {
		t.Fatalf("null cmd_prefix: %v", err)
	}
}

func TestVerifyExecLeaseHeaderKidAndFloat(t *testing.T) {
	f := newLeaseFix(t, 0o600)
	if _, err := VerifyExecLease(signTestLeaseHeader(f.priv, "", "", f.body), f.opt); err != nil {
		t.Fatalf("empty header kid: %v", err)
	}
	if _, err := VerifyExecLease(signTestLeaseHeader(f.priv, "other", "", f.body), f.opt); err != errLeaseRejected {
		t.Fatalf("header kid: %v", err)
	}
	raw := []byte(`{"v":1,"iss":"hub","kid":"hub-1","sub":"user:alice","host":"host-1","scope":"exec","cmd":["/bin/echo","hi"],"iat":1.5,"nbf":1700000000,"exp":1700000060,"jti":"jti-1"}`)
	tok := signTestLeaseRaw(f.priv, "hub-1", "EdDSA", raw)
	if _, err := VerifyExecLease(tok, f.opt); err != errLeaseRejected {
		t.Fatalf("float: %v", err)
	}
	short := signTestLease(f.priv, "hub-1", "", f.body)
	parts := strings.Split(short, ".")
	parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if _, err := VerifyExecLease(strings.Join(parts, "."), f.opt); err != errLeaseRejected {
		t.Fatalf("sig len: %v", err)
	}
}

func TestVerifyExecLeaseRecoverScope(t *testing.T) {
	f := newLeaseFix(t, 0o600)
	rec := f.body
	rec.Scope = "recover"
	rec.Cmd = nil
	opt := f.opt
	opt.Scope = "recover"
	opt.Command = nil
	if _, err := VerifyExecLease(signTestLease(f.priv, "hub-1", "", rec), opt); err != nil {
		t.Fatal(err)
	}
	rec.Cmd = mustCmd(t, "/bin/bash")
	if _, err := VerifyExecLease(signTestLease(f.priv, "hub-1", "", rec), opt); err != errLeaseRejected {
		t.Fatalf("recover cmd: %v", err)
	}
}

func TestVerifyExecLeaseRawStdKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "keys")
	body := "hub-1=ed25519:" + base64.RawStdEncoding.EncodeToString(pub) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	f := newLeaseFix(t, 0o600)
	f.priv = priv
	f.opt.KeysFile = path
	if _, err := VerifyExecLease(f.token(), f.opt); err != nil {
		t.Fatal(err)
	}
}

func TestCommitLeaseJTIReplayAndPrune(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	now := time.Unix(1_700_000_000, 0).UTC()
	if err := CommitLeaseJTI(dir, "jti-1", now.Unix()+30, now); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	if err := CommitLeaseJTI(dir, "jti-1", now.Unix()+30, now); err != errLeaseReplayed {
		t.Fatalf("replay: %v", err)
	}
	name := leaseJTIName("jti-1")
	if err := os.WriteFile(filepath.Join(dir, name), []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CommitLeaseJTI(dir, "jti-1", now.Unix()+30, now); err != errLeaseReplayed {
		t.Fatalf("garbage: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
		t.Fatal("garbage file was deleted")
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CommitLeaseJTI(dir, "jti-1", now.Unix()+30, now); err != nil {
		t.Fatalf("expired jti: %v", err)
	}
}

func TestCommitLeaseJTIRejectsLooseAndSymlink(t *testing.T) {
	loose := filepath.Join(t.TempDir(), "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CommitLeaseJTI(loose, "jti-1", 50, time.Unix(10, 0)); err != errLeaseRejected {
		t.Fatalf("0755: %v", err)
	}
	real := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := CommitLeaseJTI(link, "jti-1", 50, time.Unix(10, 0)); err != errLeaseRejected {
		t.Fatalf("symlink dir: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "files")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "other")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, leaseJTIName("jti-1"))); err != nil {
		t.Fatal(err)
	}
	if err := CommitLeaseJTI(dir, "jti-1", 50, time.Unix(10, 0)); err != errLeaseReplayed {
		t.Fatalf("symlink jti: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, leaseJTIName("jti-1"))); err != nil {
		t.Fatal(err)
	}
}

func TestVerifySignedPayloadDistinctKids(t *testing.T) {
	aPub, aPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bPub, bPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{"a": aPub, "b": bPub}
	payload := []byte(`{"v":1}`)
	one, err := signEnvelope([]testSigner{{Kid: "a", Priv: aPriv}}, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, kids, err := verifySignedPayload(one, keys, 1); err != nil || len(kids) != 1 {
		t.Fatalf("one: kids=%v err=%v", kids, err)
	}
	if _, _, err := verifySignedPayload(one, keys, 2); err == nil {
		t.Fatal("one signature counted as two")
	}
	dup, err := signEnvelope([]testSigner{{Kid: "a", Priv: aPriv}, {Kid: "a", Priv: aPriv}}, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifySignedPayload(dup, keys, 2); err == nil {
		t.Fatal("duplicate kid counted as two")
	}
	two, err := signEnvelope([]testSigner{{Kid: "a", Priv: aPriv}, {Kid: "b", Priv: bPriv}}, payload)
	if err != nil {
		t.Fatal(err)
	}
	got, kids, err := verifySignedPayload(two, keys, 2)
	if err != nil || string(got) != string(payload) || len(kids) != 2 {
		t.Fatalf("two: %v %v %s", err, kids, got)
	}
	bad := append([]byte{}, two...)
	bad[len(bad)-2] ^= 1
	if _, _, err := verifySignedPayload(bad, keys, 1); err == nil {
		t.Fatal("tampered envelope accepted")
	}
	unknown, err := signEnvelope([]testSigner{{Kid: "nope", Priv: aPriv}}, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifySignedPayload(unknown, keys, 1); err == nil {
		t.Fatal("unknown kid accepted")
	}
	huge := bytesRepeat(envelopePayloadMax + 1)
	over, err := signEnvelope([]testSigner{{Kid: "a", Priv: aPriv}}, huge)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifySignedPayload(over, keys, 1); err == nil {
		t.Fatal("oversized payload accepted")
	}
}

func bytesRepeat(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return b
}
