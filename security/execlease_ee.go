//go:build ee

// Threats: an exec or recovery lease is a bearer token. Verification pins
// Ed25519 and never reads alg from the header. A bad signature, a wrong
// key, a tampered segment, an oversized token, or a clock outside
// [nbf, exp) fails closed. The jti is single-use on disk. The token is
// never logged; callers log LeaseFingerprint. cmd_prefix is not a v1
// grant. This file does not fetch keys and does not mark the suite
// handoff wired. A verified lease is not an allow: policy still runs.
// Envelope verification for a host profile signs the raw payload bytes.
// One signature is enough until the policy or admin-key hash changes;
// a repeated kid does not count as a second person. HMAC comparison is
// not done here.
// On Darwin, replacing a jti file falls back to unlink without AT_SYMLINK_NOFOLLOW after Fstatat confirms a regular file; a symlink swapped in that window is the recorded race.
package security

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/afterdarksys/adssh/internal/safefile"
	"golang.org/x/sys/unix"
)

const (
	leaseTokenMax      = 8 * 1024
	leasePayloadMax    = 4 * 1024
	leaseHeaderMax     = 1024
	leaseWindowMax     = 300
	leaseKeysMax       = 64 * 1024
	envelopeBytesMax   = 256 * 1024
	envelopePayloadMax = 64 * 1024
)

var (
	errLeaseRequired        = errors.New("lease_required")
	errLeaseRejected        = errors.New("lease_rejected")
	errLeaseExpired         = errors.New("lease_expired")
	errLeaseReplayed        = errors.New("lease_replayed")
	errLeaseCommandMismatch = errors.New("lease_command_mismatch")

	errSignedPayload = errors.New("signed payload rejected")

	jtiPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

	leaseStateMu sync.Mutex
)

// LeaseOptions pins the verifier. Empty keys, issuer, host, or an unknown
// scope fail closed. Now zero means time.Now().UTC().
type LeaseOptions struct {
	KeysFile string
	Issuer   string
	HostID   string
	Scope    string
	Command  []string
	Now      time.Time
}

// VerifiedLease is what a signature proved. Claim is what policy may read.
type VerifiedLease struct {
	Sub   string
	Host  string
	JTI   string
	Exp   int64
	Scope string
	Kid   string
	Cmd   []string
}

// Claim returns the policy-visible subject. The token is not included.
func (v VerifiedLease) Claim() *ExecLeaseClaim {
	return &ExecLeaseClaim{Sub: v.Sub, Host: v.Host, JTI: v.JTI, Exp: v.Exp}
}

type leaseHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
}

type leasePayload struct {
	V         int             `json:"v"`
	Iss       string          `json:"iss"`
	Kid       string          `json:"kid"`
	Sub       string          `json:"sub"`
	Host      string          `json:"host"`
	Scope     string          `json:"scope"`
	Cmd       json.RawMessage `json:"cmd,omitempty"`
	CmdPrefix json.RawMessage `json:"cmd_prefix,omitempty"`
	Iat       int64           `json:"iat"`
	Nbf       int64           `json:"nbf"`
	Exp       int64           `json:"exp"`
	JTI       string          `json:"jti"`
}

type envelopeSig struct {
	Kid string `json:"kid"`
	Sig string `json:"sig"`
}

type signedEnvelope struct {
	Payload string        `json:"payload"`
	Sigs    []envelopeSig `json:"sigs"`
}

// LeaseFingerprint is the SHA-256 hex of the token. Log this, never the token.
func LeaseFingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// VerifyExecLease checks a compact JWS. It does not consume the jti.
// Error() is exactly one of the lease_* codes.
func VerifyExecLease(token string, opt LeaseOptions) (VerifiedLease, error) {
	if opt.KeysFile == "" || opt.Issuer == "" || opt.HostID == "" {
		return VerifiedLease{}, errLeaseRejected
	}
	if opt.Scope != "exec" && opt.Scope != "recover" {
		return VerifiedLease{}, errLeaseRejected
	}
	if token == "" || len(token) > leaseTokenMax || hasSpace(token) {
		return VerifiedLease{}, errLeaseRejected
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return VerifiedLease{}, errLeaseRejected
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(headerRaw) == 0 || len(headerRaw) > leaseHeaderMax {
		return VerifiedLease{}, errLeaseRejected
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payloadRaw) == 0 || len(payloadRaw) > leasePayloadMax {
		return VerifiedLease{}, errLeaseRejected
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return VerifiedLease{}, errLeaseRejected
	}
	var hdr leaseHeader
	if err := unmarshalStrict(headerRaw, &hdr); err != nil {
		return VerifiedLease{}, errLeaseRejected
	}
	var payload leasePayload
	if err := unmarshalStrict(payloadRaw, &payload); err != nil {
		return VerifiedLease{}, errLeaseRejected
	}
	keys, err := loadEd25519Keys(opt.KeysFile)
	if err != nil {
		return VerifiedLease{}, errLeaseRejected
	}
	pub, ok := keys[payload.Kid]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return VerifiedLease{}, errLeaseRejected
	}
	signing := parts[0] + "." + parts[1]
	if !ed25519.Verify(pub, []byte(signing), sig) {
		return VerifiedLease{}, errLeaseRejected
	}
	if hdr.Kid != "" && hdr.Kid != payload.Kid {
		return VerifiedLease{}, errLeaseRejected
	}
	if len(payload.CmdPrefix) != 0 {
		return VerifiedLease{}, errLeaseRejected
	}
	if payload.V != 1 || payload.Scope != opt.Scope {
		return VerifiedLease{}, errLeaseRejected
	}
	if payload.Iss != opt.Issuer || payload.Host != opt.HostID {
		return VerifiedLease{}, errLeaseRejected
	}
	if payload.Iss == "" || payload.Sub == "" || payload.Host == "" || payload.Kid == "" {
		return VerifiedLease{}, errLeaseRejected
	}
	if hasBadText(payload.Iss) || hasBadText(payload.Sub) || hasBadText(payload.Host) {
		return VerifiedLease{}, errLeaseRejected
	}
	if !jtiPattern.MatchString(payload.JTI) {
		return VerifiedLease{}, errLeaseRejected
	}
	var cmd []string
	if opt.Scope == "recover" {
		if len(payload.Cmd) != 0 || len(opt.Command) != 0 {
			return VerifiedLease{}, errLeaseRejected
		}
	} else {
		parsed, perr := parseLeaseCmd(payload.Cmd)
		if perr != nil {
			return VerifiedLease{}, errLeaseRejected
		}
		cmd = parsed
	}
	now := opt.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nowUnix := now.Unix()
	if payload.Iat <= 0 || payload.Nbf <= 0 || payload.Exp <= 0 {
		return VerifiedLease{}, errLeaseRejected
	}
	if payload.Iat > payload.Nbf || payload.Nbf > payload.Exp || payload.Exp <= payload.Iat {
		return VerifiedLease{}, errLeaseRejected
	}
	if payload.Exp-payload.Iat > leaseWindowMax {
		return VerifiedLease{}, errLeaseRejected
	}
	if payload.Iat > nowUnix || nowUnix < payload.Nbf {
		return VerifiedLease{}, errLeaseRejected
	}
	if nowUnix >= payload.Exp {
		return VerifiedLease{}, errLeaseExpired
	}
	if opt.Scope == "exec" && !cmdsEqual(cmd, opt.Command) {
		return VerifiedLease{}, errLeaseCommandMismatch
	}
	return VerifiedLease{
		Sub:   payload.Sub,
		Host:  payload.Host,
		JTI:   payload.JTI,
		Exp:   payload.Exp,
		Scope: payload.Scope,
		Kid:   payload.Kid,
		Cmd:   cmd,
	}, nil
}

// CommitLeaseJTI records jti until exp. A second commit before exp is
// lease_replayed. An expired record is removed and the new exp is stored.
// The directory must be owner-only. Error() is a lease_* code.
func CommitLeaseJTI(dir, jti string, exp int64, now time.Time) error {
	if !jtiPattern.MatchString(jti) || exp <= 0 || dir == "" || strings.ContainsRune(dir, 0) {
		return errLeaseRejected
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	leaseStateMu.Lock()
	defer leaseStateMu.Unlock()
	dirfd, err := openLeaseStateDir(dir)
	if err != nil {
		return errLeaseRejected
	}
	name := leaseJTIName(jti)
	commitErr := consumeLeaseJTI(dirfd, name, exp, now.Unix(), 0)
	if cerr := unix.Close(dirfd); cerr != nil && commitErr == nil {
		return errLeaseRejected
	}
	return commitErr
}

func openLeaseStateDir(dir string) (int, error) {
	fi, err := os.Lstat(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			return -1, err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return -1, err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return -1, err
		}
		fi, err = os.Lstat(dir)
		if err != nil {
			return -1, err
		}
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return -1, errLeaseRejected
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return -1, errLeaseRejected
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	return fd, nil
}

func consumeLeaseJTI(dirfd int, name string, exp, now int64, attempt int) error {
	fd, err := unix.Openat(dirfd, name, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return existingLeaseJTI(dirfd, name, exp, now, attempt)
		}
		if errors.Is(err, unix.ELOOP) {
			return errLeaseReplayed
		}
		return errLeaseRejected
	}
	body := []byte(strconv.FormatInt(exp, 10))
	werr := writeFull(fd, body)
	cerr := unix.Close(fd)
	if werr != nil || cerr != nil {
		if uerr := unlinkLeaseName(dirfd, name); uerr != nil {
			return errLeaseRejected
		}
		return errLeaseRejected
	}
	return nil
}

func existingLeaseJTI(dirfd int, name string, exp, now int64, attempt int) error {
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errLeaseReplayed
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		if cerr := unix.Close(fd); cerr != nil {
			return errLeaseReplayed
		}
		return errLeaseReplayed
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		if cerr := unix.Close(fd); cerr != nil {
			return errLeaseReplayed
		}
		return errLeaseReplayed
	}
	buf := make([]byte, 64)
	n, rerr := unix.Read(fd, buf)
	cerr := unix.Close(fd)
	if rerr != nil || cerr != nil || n <= 0 || n == len(buf) {
		return errLeaseReplayed
	}
	stored, perr := strconv.ParseInt(strings.TrimSpace(string(buf[:n])), 10, 64)
	if perr != nil {
		return errLeaseReplayed
	}
	if stored > now {
		return errLeaseReplayed
	}
	if attempt > 0 {
		return errLeaseReplayed
	}
	if err := unlinkLeaseName(dirfd, name); err != nil {
		return errLeaseReplayed
	}
	return consumeLeaseJTI(dirfd, name, exp, now, attempt+1)
}

// unlinkLeaseName removes a regular file. Linux honors
// AT_SYMLINK_NOFOLLOW. Darwin returns EINVAL for that flag, so the
// fallback stats with AT_SYMLINK_NOFOLLOW and unlinks only a regular file.
func unlinkLeaseName(dirfd int, name string) error {
	err := unix.Unlinkat(dirfd, name, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil || !errors.Is(err, unix.EINVAL) {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return unix.ELOOP
	}
	return unix.Unlinkat(dirfd, name, 0)
}

func writeFull(fd int, b []byte) error {
	for len(b) > 0 {
		n, err := unix.Write(fd, b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func leaseJTIName(jti string) string {
	sum := sha256.Sum256([]byte(jti))
	return hex.EncodeToString(sum[:])
}

func parseLeaseCmd(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, errLeaseRejected
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var cmd []string
	if err := dec.Decode(&cmd); err != nil || len(cmd) == 0 {
		return nil, errLeaseRejected
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errLeaseRejected
	}
	for _, arg := range cmd {
		if strings.ContainsRune(arg, 0) {
			return nil, errLeaseRejected
		}
	}
	return cmd, nil
}

func cmdsEqual(a, b []string) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hasSpace(s string) bool {
	for _, r := range s {
		if unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

func hasBadText(s string) bool {
	return strings.ContainsRune(s, 0) || strings.ContainsAny(s, "\n\r")
}

// loadEd25519Keys reads kid=ed25519:<base64> lines. The error is generic so
// a host-profile caller can map every failure to profile_rejected.
func loadEd25519Keys(path string) (keys map[string]ed25519.PublicKey, err error) {
	if path == "" || strings.ContainsRune(path, 0) {
		return nil, errors.New("keys path is empty")
	}
	f, info, err := safefile.Open(nil, path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
			keys = nil
		}
	}()
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("keys file is not owner-only")
	}
	body, err := safefile.ReadAll(f, info, leaseKeysMax)
	if err != nil {
		return nil, err
	}
	keys = map[string]ed25519.PublicKey{}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, "=ed25519:")
		if idx <= 0 {
			return nil, errors.New("keys file is malformed")
		}
		kid := line[:idx]
		raw := line[idx+len("=ed25519:"):]
		if kid == "" || raw == "" || strings.ContainsRune(kid, 0) || strings.ContainsAny(kid, " \t") {
			return nil, errors.New("keys file is malformed")
		}
		pub, err := decodePub(raw)
		if err != nil {
			return nil, err
		}
		if _, dup := keys[kid]; dup {
			return nil, errors.New("keys file has a duplicate kid")
		}
		keys[kid] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("keys file is empty")
	}
	return keys, nil
}

func decodePub(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return nil, errors.New("keys file has a bad public key")
		}
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, errors.New("keys file has a bad public key")
	}
	out := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(out, b)
	return out, nil
}

func unmarshalStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("trailing json")
		}
		return err
	}
	return nil
}

// verifySignedPayload checks an envelope. Callers pass minDistinct 1. A
// second person is the caller’s check on the returned kids when the policy
// or admin-key hash changes. Every signature must verify. A repeated kid
// does not count. Kids are returned in first-seen order.
func verifySignedPayload(envBytes []byte, keys map[string]ed25519.PublicKey, minDistinct int) ([]byte, []string, error) {
	if minDistinct < 1 || len(envBytes) == 0 || len(envBytes) > envelopeBytesMax || len(keys) == 0 {
		return nil, nil, errSignedPayload
	}
	var env signedEnvelope
	if err := unmarshalStrict(envBytes, &env); err != nil {
		return nil, nil, errSignedPayload
	}
	if len(env.Sigs) == 0 || env.Payload == "" {
		return nil, nil, errSignedPayload
	}
	payload, err := decodeStdOrRaw(env.Payload)
	if err != nil || len(payload) == 0 || len(payload) > envelopePayloadMax {
		return nil, nil, errSignedPayload
	}
	seen := map[string]struct{}{}
	kids := make([]string, 0, len(env.Sigs))
	for _, sig := range env.Sigs {
		pub, ok := keys[sig.Kid]
		if !ok || sig.Kid == "" || len(pub) != ed25519.PublicKeySize {
			return nil, nil, errSignedPayload
		}
		raw, err := decodeStdOrRaw(sig.Sig)
		if err != nil || len(raw) != ed25519.SignatureSize {
			return nil, nil, errSignedPayload
		}
		if !ed25519.Verify(pub, payload, raw) {
			return nil, nil, errSignedPayload
		}
		if _, dup := seen[sig.Kid]; !dup {
			seen[sig.Kid] = struct{}{}
			kids = append(kids, sig.Kid)
		}
	}
	if len(kids) < minDistinct {
		return nil, nil, errSignedPayload
	}
	return payload, kids, nil
}

func decodeStdOrRaw(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

type testSigner struct {
	Kid  string
	Priv ed25519.PrivateKey
}

func signEnvelope(signers []testSigner, payload []byte) ([]byte, error) {
	env := signedEnvelope{Payload: base64.StdEncoding.EncodeToString(payload)}
	for _, s := range signers {
		sig := ed25519.Sign(s.Priv, payload)
		env.Sigs = append(env.Sigs, envelopeSig{
			Kid: s.Kid,
			Sig: base64.StdEncoding.EncodeToString(sig),
		})
	}
	return json.Marshal(env)
}

func signTestLease(priv ed25519.PrivateKey, kid, headerAlg string, payload any) string {
	return signTestLeaseHeader(priv, kid, headerAlg, payload)
}

func signTestLeaseHeader(priv ed25519.PrivateKey, headerKid, headerAlg string, payload any) string {
	body, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return signTestLeaseRaw(priv, headerKid, headerAlg, body)
}

func signTestLeaseRaw(priv ed25519.PrivateKey, headerKid, headerAlg string, payload []byte) string {
	if headerAlg == "" {
		headerAlg = "EdDSA"
	}
	hb, err := json.Marshal(leaseHeader{Alg: headerAlg, Kid: headerKid})
	if err != nil {
		panic(err)
	}
	h := base64.RawURLEncoding.EncodeToString(hb)
	p := base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(priv, []byte(h+"."+p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}
