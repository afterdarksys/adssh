// Package sashparent is the emergency parent of sash.
//
// Threats: a fleet key signing purpose emergency, adssh signing terminal:open
// or terminal:root, identical purpose keys, a missing or group-readable seed,
// a symlink in place of the seed or the fleet public key, and a missing sash
// binary. This parent signs only purpose emergency with the per-host seed and
// execs sash on fds 3-6. It does NOT hold the fleet private key, does NOT
// import github.com/afterdarksys/sash, does NOT run a helper, and does NOT
// log the seed, the signature, or the document. The seed is not placed in
// the child environment or on fds 3-6. Every verb is answered denied.
package sashparent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	purposeEmergency = "emergency"
	domain           = "sash-grant-v1\n"
	maxFrame         = 8 << 20
)

// Error is a fixed token. Its text is safe to print. It never carries a path,
// a seed, or a document.
type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrMissing  Error = "grant_missing"
	ErrBadShape Error = "grant_bad_shape"
	ErrStar     Error = "grant_star"
	ErrBadSig   Error = "grant_bad_sig"
	ErrSashMiss Error = "sash_missing"
	ErrParent   Error = "sash emergency parent failed"
)

// Grant is the unsigned emergency document. Purpose is not a field: the only
// signer that production calls hardcodes purpose emergency.
type Grant struct {
	Actor        string
	Host         string
	Exp          int64
	LeaseID      string
	Entitlements []string
	FileRead     []string
	FileWrite    []string
	AllowPrivate bool
}

type signed struct {
	V            string   `json:"v"`
	Actor        string   `json:"actor"`
	Host         string   `json:"host"`
	Purpose      string   `json:"purpose"`
	Exp          int64    `json:"exp"`
	LeaseID      string   `json:"lease_id"`
	Entitlements []string `json:"entitlements"`
	FileRead     []string `json:"file_read"`
	FileWrite    []string `json:"file_write"`
	AllowPrivate bool     `json:"allow_private"`
}

type wire struct {
	signed
	Sig string `json:"sig"`
}

type verbReq struct {
	Key  string   `json:"key"`
	Argv []string `json:"argv"`
	Path string   `json:"path"`
	Body string   `json:"body"`
}

type denyResp struct {
	Error string `json:"error"`
}

// Zero wipes a seed or a private key.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SignEmergency signs purpose emergency. It has no purpose argument.
// A "*" entitlement returns grant_star and a nil document, with no signature.
// allow_private on the result is false.
func SignEmergency(g Grant, seed []byte) ([]byte, ed25519.PublicKey, error) {
	g.AllowPrivate = false
	if err := shape(g); err != nil {
		return nil, nil, err
	}
	if starred(g.Entitlements) {
		return nil, nil, ErrStar
	}
	if len(seed) != ed25519.SeedSize {
		return nil, nil, ErrBadSig
	}
	var seedCopy [ed25519.SeedSize]byte
	copy(seedCopy[:], seed)
	priv := ed25519.NewKeyFromSeed(seedCopy[:])
	Zero(seedCopy[:])
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pub, priv[ed25519.SeedSize:])
	doc, err := signWith(purposeEmergency, g, priv)
	Zero(priv)
	if err != nil {
		return nil, nil, err
	}
	return doc, pub, nil
}

// signWith signs an already-shaped grant for tests that must prove the wrong
// key fails. Production calls SignEmergency, which only passes purpose emergency.
func signWith(purpose string, g Grant, priv ed25519.PrivateKey) ([]byte, error) {
	if err := shape(g); err != nil {
		return nil, err
	}
	if starred(g.Entitlements) {
		return nil, ErrStar
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, ErrBadSig
	}
	body, err := json.Marshal(signed{
		V:            "sash/1",
		Actor:        g.Actor,
		Host:         g.Host,
		Purpose:      purpose,
		Exp:          g.Exp,
		LeaseID:      g.LeaseID,
		Entitlements: norm(g.Entitlements),
		FileRead:     norm(g.FileRead),
		FileWrite:    norm(g.FileWrite),
		AllowPrivate: g.AllowPrivate,
	})
	if err != nil {
		return nil, ErrBadShape
	}
	msg := make([]byte, 0, len(domain)+len(body))
	msg = append(msg, domain...)
	msg = append(msg, body...)
	sig := ed25519.Sign(priv, msg)
	doc, err := json.Marshal(wire{
		signed: signed{
			V:            "sash/1",
			Actor:        g.Actor,
			Host:         g.Host,
			Purpose:      purpose,
			Exp:          g.Exp,
			LeaseID:      g.LeaseID,
			Entitlements: norm(g.Entitlements),
			FileRead:     norm(g.FileRead),
			FileWrite:    norm(g.FileWrite),
			AllowPrivate: g.AllowPrivate,
		},
		Sig: base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		return nil, ErrBadShape
	}
	return doc, nil
}

func shape(g Grant) error {
	if !canonID(g.Actor) || !canonID(g.Host) || !canonID(g.LeaseID) || g.Exp <= 0 {
		return ErrBadShape
	}
	if g.Entitlements == nil {
		return ErrBadShape
	}
	for _, name := range g.Entitlements {
		if !canonText(name) {
			return ErrBadShape
		}
	}
	if err := roots(g.FileRead); err != nil {
		return err
	}
	return roots(g.FileWrite)
}

func canonID(s string) bool {
	if strings.ContainsRune(s, '=') {
		return false
	}
	return canonText(s)
}

func canonText(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r > 0x7e || r == '<' || r == '>' || r == '&' {
			return false
		}
	}
	return true
}

func roots(list []string) error {
	for _, r := range list {
		if !canonText(r) || path.Clean(r) != r || !strings.HasPrefix(r, "/") {
			return ErrBadShape
		}
	}
	return nil
}

func starred(list []string) bool {
	for _, name := range list {
		if name == "*" {
			return true
		}
	}
	return false
}

func norm(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// GrantFromEnv reads the binding the agent put in the environment.
// Entitlements are an empty list. A past exp is still returned so sash
// itself answers grant_expired. now is the caller's clock and is not used
// to reject a past exp.
func GrantFromEnv(getenv func(string) string, _ time.Time) (Grant, error) {
	expRaw := getenv("ADSSH_SASH_EXP")
	exp, err := strconv.ParseInt(expRaw, 10, 64)
	if err != nil || exp <= 0 || strconv.FormatInt(exp, 10) != expRaw {
		return Grant{}, ErrBadShape
	}
	g := Grant{
		Actor:        getenv("ADSSH_SASH_ACTOR"),
		Host:         getenv("ADSSH_SASH_HOST"),
		LeaseID:      getenv("ADSSH_SASH_LEASE"),
		Exp:          exp,
		Entitlements: []string{},
		FileRead:     []string{},
		FileWrite:    []string{},
	}
	if err := shape(g); err != nil {
		return Grant{}, err
	}
	return g, nil
}

// ReadKeyFiles reads the raw 32-byte emergency seed and the raw 32-byte
// fleet public key. A symlink, a non-regular file, a missing file, a short
// file, or a seed that is group- or world-readable is grant_bad_sig.
// The fleet public key may be world-readable. The caller zeros seed.
func ReadKeyFiles(seedPath, fleetPath string) ([]byte, ed25519.PublicKey, error) {
	seed, err := readKeyFile(seedPath, true)
	if err != nil {
		return nil, nil, err
	}
	fleet, err := readKeyFile(fleetPath, false)
	if err != nil {
		Zero(seed)
		return nil, nil, err
	}
	return seed, ed25519.PublicKey(fleet), nil
}

func readKeyFile(path string, ownerOnly bool) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return nil, ErrBadSig
	}
	if ownerOnly && fi.Mode().Perm()&0o077 != 0 {
		return nil, ErrBadSig
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrBadSig
	}
	st, statErr := f.Stat()
	bad := statErr != nil || !os.SameFile(fi, st) || !st.Mode().IsRegular()
	if !bad && ownerOnly && st.Mode().Perm()&0o077 != 0 {
		bad = true
	}
	var buf []byte
	var readErr error
	if !bad {
		buf, readErr = io.ReadAll(io.LimitReader(f, ed25519.PublicKeySize+1))
	}
	closeErr := f.Close()
	if closeErr != nil && !gone(closeErr) {
		return nil, ErrBadSig
	}
	if bad || readErr != nil || len(buf) != ed25519.PublicKeySize {
		return nil, ErrBadSig
	}
	return buf, nil
}

// Run execs bin with args and the session fds. A refusal before exec returns
// a token and does not start the process. When the child runs, the returned
// error is nil and the code is the child's, including exit 2 after sash
// printed its own token. fds: 3 grant, 4 fleet public key, 5 emergency
// public key, 6 verb socket. The verb server answers only {"error":"denied"}.
func Run(bin string, args []string, doc, fleetPub, emerPub []byte, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	st, err := os.Stat(bin)
	if err != nil || st.IsDir() {
		return 0, ErrSashMiss
	}
	if len(doc) == 0 {
		return 0, ErrMissing
	}
	if !distinct(fleetPub, emerPub) {
		return 0, ErrBadSig
	}

	grantR, grantW, err := os.Pipe()
	if err != nil {
		return 0, ErrParent
	}
	fleetR, fleetW, err := os.Pipe()
	if err != nil {
		return 0, joinClose(ErrParent, grantR, grantW)
	}
	emerR, emerW, err := os.Pipe()
	if err != nil {
		return 0, joinClose(ErrParent, grantR, grantW, fleetR, fleetW)
	}
	sp, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return 0, joinClose(ErrParent, grantR, grantW, fleetR, fleetW, emerR, emerW)
	}
	syscall.CloseOnExec(sp[0])
	syscall.CloseOnExec(sp[1])
	parentVerb := os.NewFile(uintptr(sp[0]), "sash-verb-parent")
	childVerb := os.NewFile(uintptr(sp[1]), "sash-verb-child")
	if parentVerb == nil || childVerb == nil {
		return 0, joinClose(ErrParent, grantR, grantW, fleetR, fleetW, emerR, emerW, parentVerb, childVerb)
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- serveDeny(parentVerb)
	}()
	stopServe := func() error {
		cerr := closeFile(parentVerb)
		serr := cleanServe(<-serveErr)
		if cerr != nil {
			return ErrParent
		}
		if serr != nil {
			return ErrParent
		}
		return nil
	}

	if err := writeAll(grantW, doc); err != nil {
		return 0, firstErr(stopServe(), joinClose(ErrParent, grantR, grantW, fleetR, fleetW, emerR, emerW, childVerb))
	}
	if err := writeAll(fleetW, fleetPub); err != nil {
		return 0, firstErr(stopServe(), joinClose(ErrParent, grantR, grantW, fleetR, fleetW, emerR, emerW, childVerb))
	}
	if err := writeAll(emerW, emerPub); err != nil {
		return 0, firstErr(stopServe(), joinClose(ErrParent, grantR, grantW, fleetR, fleetW, emerR, emerW, childVerb))
	}
	if err := joinClose(nil, grantW, fleetW, emerW); err != nil {
		return 0, firstErr(stopServe(), joinClose(ErrParent, grantR, fleetR, emerR, childVerb))
	}

	cmd := exec.Command(bin, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.ExtraFiles = []*os.File{grantR, fleetR, emerR, childVerb}
	if err := cmd.Start(); err != nil {
		return 0, firstErr(stopServe(), joinClose(ErrParent, grantR, fleetR, emerR, childVerb))
	}
	if err := joinClose(nil, grantR, fleetR, emerR, childVerb); err != nil {
		waitErr := cmd.Wait()
		serveFail := stopServe()
		if waitErr == nil && serveFail == nil {
			return 0, ErrParent
		}
		if code, ok := childCode(waitErr); ok {
			if serveFail != nil {
				return 0, ErrParent
			}
			return code, ErrParent
		}
		return 0, ErrParent
	}
	waitErr := cmd.Wait()
	serveFail := stopServe()
	code, ok := childCode(waitErr)
	if !ok || serveFail != nil {
		return 0, ErrParent
	}
	return code, nil
}

func childCode(err error) (int, bool) {
	if err == nil {
		return 0, true
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), true
	}
	return 0, false
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return ErrParent
}

func joinClose(base error, files ...*os.File) error {
	for _, f := range files {
		if err := closeFile(f); err != nil && base == nil {
			base = ErrParent
		}
	}
	return base
}

func closeFile(f *os.File) error {
	if f == nil {
		return nil
	}
	err := f.Close()
	if err == nil || gone(err) {
		return nil
	}
	return err
}

func gone(err error) bool {
	return errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EBADF)
}

func distinct(a, b []byte) bool {
	if len(a) != ed25519.PublicKeySize || len(b) != ed25519.PublicKeySize {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 0
}

func serveDeny(rw io.ReadWriter) error {
	for {
		var req verbReq
		err := readFrame(rw, &req)
		if err == nil {
			if werr := writeFrame(rw, denyResp{Error: "denied"}); werr != nil {
				return werr
			}
			continue
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || gone(err) {
			return nil
		}
		if err.Error() == "frame too large" {
			return err
		}
		if werr := writeFrame(rw, denyResp{Error: "denied"}); werr != nil {
			return werr
		}
	}
}

func cleanServe(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || gone(err) {
		return nil
	}
	return err
}

func readFrame(r io.Reader, v any) error {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size > maxFrame {
		return errors.New("frame too large")
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("frame body")
	}
	return nil
}

func writeFrame(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(body) > maxFrame {
		return errors.New("frame too large")
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(body)))
	if err := writeAll(w, n[:]); err != nil {
		return err
	}
	return writeAll(w, body)
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n > 0 {
			b = b[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
