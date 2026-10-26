//go:build ee

// Threats: a host profile is signed. One signature may change the user list.
// A change to policy_hash or admin_keys_hash needs two distinct signers when
// a profile is already installed. An unsigned overlay can only narrow, and
// it cannot change hashes or the host id. A bad signature, a symlink, a mode
// other than owner-only, or an empty ADSSH_HOST_ID on commit or rollback is
// profile_rejected. chmod failure is returned as-is and does not restore the
// previous profile. Agents cannot run host. Recovery and quarantine refuse
// commit and rollback.
// Non-goals: host does not start sshd and does not treat a lease id as
// authorization. Widening is not an emergency allow-all.

package security

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/afterdarksys/adssh/internal/safefile"
)

type hostProfile struct {
	V             int      `json:"v"`
	Host          string   `json:"host"`
	Users         []string `json:"users"`
	Listeners     []string `json:"listeners"`
	Packages      []string `json:"packages"`
	Sysctls       []string `json:"sysctls"`
	Units         []string `json:"units"`
	PolicyHash    string   `json:"policy_hash"`
	AdminKeysHash string   `json:"admin_keys_hash"`
}

var (
	errProfileRejected = errors.New("host: profile_rejected")
	errProfileWiden    = errors.New("host: profile_widen")
	hostChmod          = os.Chmod
)

// chmodError is the chmod failure from writePrivate. It is a value so
// errors.As can match it. The installed path is already removed.
type chmodError struct{ err error }

func (e chmodError) Error() string {
	if e.err == nil {
		return "chmod"
	}
	return e.err.Error()
}

func (e chmodError) Unwrap() error { return e.err }

type hostBinary struct{}

func (hostBinary) Name() string        { return "host" }
func (hostBinary) Description() string { return "Signed host profile" }
func (hostBinary) Usage() string {
	return "host: usage: host <drift|status|verify|commit|rollback> [FILE]"
}

func (hostBinary) Run(ctx context.Context, args []string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if helpArgs(args) {
		return writeOut(ctx, hostBinary{}.Usage())
	}
	sub, file, err := parseHost(args)
	if err != nil {
		return err
	}
	sid, sess, err := requireSession(ctx, "host")
	if err != nil {
		return err
	}
	if sess.ManagedAgent() != nil {
		return errors.New("host: agents cannot run host")
	}
	if (inRecover(ctx) || quarantineActive()) && (sub == "commit" || sub == "rollback") {
		return errors.New("host: refused")
	}
	switch sub {
	case "drift", "status":
		return hostDrift(ctx, sid, sub)
	case "verify":
		return hostVerify(ctx, sid)
	case "commit":
		return hostCommit(ctx, sid, file)
	case "rollback":
		return hostRollback(ctx, sid)
	default:
		return errors.New(hostBinary{}.Usage())
	}
}

func parseHost(args []string) (sub, file string, err error) {
	usage := errors.New("host: usage: host <drift|status|verify|commit|rollback> [FILE]")
	if len(args) < 2 {
		return "", "", usage
	}
	switch args[1] {
	case "drift", "status", "verify", "rollback":
		if len(args) != 2 {
			return "", "", usage
		}
		return args[1], "", nil
	case "commit":
		if len(args) != 3 || args[2] == "" {
			return "", "", usage
		}
		return "commit", args[2], nil
	default:
		return "", "", usage
	}
}

func hostCommit(ctx context.Context, sid, file string) error {
	if os.Getenv("ADSSH_HOST_ID") == "" {
		return errProfileRejected
	}
	instPath := hostProfilePath()
	if instPath == "" {
		return errProfileRejected
	}
	raw, err := readCandidate(file)
	if err != nil {
		return errProfileRejected
	}
	p, kids, signed, err := parseCandidate(raw)
	if err != nil {
		return err
	}
	if err := checkHostID(p.Host, true); err != nil {
		return err
	}
	_, lerr := os.Lstat(instPath)
	exists := lerr == nil
	if lerr != nil && !os.IsNotExist(lerr) {
		return errProfileRejected
	}
	var installed hostProfile
	if exists {
		if hostPrevPath() == "" {
			return errProfileRejected
		}
		installed, err = readInstalledSigned()
		if err != nil {
			return err
		}
		if p.Host != installed.Host {
			return errProfileRejected
		}
	}
	if !signed {
		return commitNarrow(ctx, sid, file, raw, p, installed, exists)
	}
	if needsTwo(installed, p, exists) && len(kids) < 2 {
		return errProfileWiden
	}
	eng := engineFromContext(ctx)
	if err := eng.AuthorizeCommand([]string{"host", "commit", file}, sid); err != nil {
		return err
	}
	if err := eng.LogEvent(profileLog("HOST_PROFILE", p)); err != nil {
		return fmt.Errorf("adssh: audit log failed: %w", err)
	}
	if exists {
		if err := os.Rename(instPath, hostPrevPath()); err != nil {
			return errProfileRejected
		}
	}
	return mapHostWrite(writePrivate(instPath, raw))
}

func commitNarrow(ctx context.Context, sid, file string, raw []byte, overlay, installed hostProfile, exists bool) error {
	if !exists {
		return errProfileWiden
	}
	if overlay.Host != installed.Host {
		return errProfileRejected
	}
	if !narrowOf(overlay, installed) {
		return errProfileWiden
	}
	eng := engineFromContext(ctx)
	if err := eng.AuthorizeCommand([]string{"host", "commit", file}, sid); err != nil {
		return err
	}
	if err := eng.LogEvent(profileLog("HOST_PROFILE_NARROW", overlay)); err != nil {
		return fmt.Errorf("adssh: audit log failed: %w", err)
	}
	narrow := hostNarrowPath()
	if narrow == "" {
		return errProfileRejected
	}
	return mapHostWrite(writePrivate(narrow, raw))
}

func hostDrift(ctx context.Context, sid, sub string) error {
	body, err := readOwnerOnly(hostProfilePath(), envelopeBytesMax)
	if err != nil {
		if os.IsNotExist(err) {
			return driftMissing()
		}
		return errProfileRejected
	}
	if !looksSigned(body) {
		return errProfileRejected
	}
	keys, err := loadEd25519Keys(hostKeysPath())
	if err != nil {
		return errProfileRejected
	}
	p, _, err := parseSigned(body, keys)
	if err != nil {
		return errProfileRejected
	}
	if err := checkHostID(p.Host, false); err != nil {
		return err
	}
	p, err = applyNarrow(p)
	if err != nil {
		return err
	}
	eng := engineFromContext(ctx)
	if err := eng.AuthorizeCommand([]string{"host", sub}, sid); err != nil {
		return err
	}
	if err := eng.LogEvent(profileLog("HOST_PROFILE", p)); err != nil {
		return fmt.Errorf("adssh: audit log failed: %w", err)
	}
	return writeOut(ctx, formatProfile(p))
}

func driftMissing() error {
	path := hostNarrowPath()
	if path == "" {
		return errProfileRejected
	}
	body, err := readCandidate(path)
	if err != nil {
		return errProfileRejected
	}
	if looksSigned(body) {
		return errProfileRejected
	}
	if _, err := parseUnsigned(body); err != nil {
		return err
	}
	return errProfileWiden
}

func hostVerify(ctx context.Context, sid string) error {
	body, err := readOwnerOnly(hostProfilePath(), envelopeBytesMax)
	if err != nil {
		return errProfileRejected
	}
	if !looksSigned(body) {
		return errProfileRejected
	}
	keys, err := loadEd25519Keys(hostKeysPath())
	if err != nil {
		return errProfileRejected
	}
	p, _, err := parseSigned(body, keys)
	if err != nil {
		return errProfileRejected
	}
	if err := checkHostID(p.Host, false); err != nil {
		return err
	}
	eng := engineFromContext(ctx)
	if err := eng.AuthorizeCommand([]string{"host", "verify"}, sid); err != nil {
		return err
	}
	if err := eng.LogEvent(profileLog("HOST_PROFILE", p)); err != nil {
		return fmt.Errorf("adssh: audit log failed: %w", err)
	}
	return writeOut(ctx, formatProfile(p)+"host: verified\n")
}

func hostRollback(ctx context.Context, sid string) error {
	if os.Getenv("ADSSH_HOST_ID") == "" {
		return errProfileRejected
	}
	instPath := hostProfilePath()
	if instPath == "" {
		return errProfileRejected
	}
	body, err := readOwnerOnly(hostPrevPath(), envelopeBytesMax)
	if err != nil {
		return errProfileRejected
	}
	if !looksSigned(body) {
		return errProfileRejected
	}
	keys, err := loadEd25519Keys(hostKeysPath())
	if err != nil {
		return errProfileRejected
	}
	p, _, err := parseSigned(body, keys)
	if err != nil {
		return errProfileRejected
	}
	if err := checkHostID(p.Host, true); err != nil {
		return err
	}
	eng := engineFromContext(ctx)
	if err := eng.AuthorizeCommand([]string{"host", "rollback"}, sid); err != nil {
		return err
	}
	if err := eng.LogEvent(profileLog("HOST_PROFILE", p)); err != nil {
		return fmt.Errorf("adssh: audit log failed: %w", err)
	}
	return mapHostWrite(writePrivate(instPath, body))
}

func parseCandidate(raw []byte) (hostProfile, []string, bool, error) {
	if looksSigned(raw) {
		keys, err := loadEd25519Keys(hostKeysPath())
		if err != nil {
			return hostProfile{}, nil, true, errProfileRejected
		}
		p, kids, err := parseSigned(raw, keys)
		if err != nil {
			return hostProfile{}, nil, true, errProfileRejected
		}
		return p, kids, true, nil
	}
	p, err := parseUnsigned(raw)
	if err != nil {
		return hostProfile{}, nil, false, err
	}
	return p, nil, false, nil
}

func parseSigned(body []byte, keys map[string]ed25519.PublicKey) (hostProfile, []string, error) {
	payload, kids, err := verifySignedPayload(body, keys, 1)
	if err != nil {
		return hostProfile{}, nil, errProfileRejected
	}
	p, err := decodeProfile(payload)
	if err != nil {
		return hostProfile{}, nil, errProfileRejected
	}
	return p, kids, nil
}

func parseUnsigned(body []byte) (hostProfile, error) {
	p, err := decodeProfile(body)
	if err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return hostProfile{}, errProfileWiden
		}
		return hostProfile{}, errProfileRejected
	}
	return p, nil
}

func decodeProfile(body []byte) (hostProfile, error) {
	var p hostProfile
	if err := unmarshalStrict(body, &p); err != nil {
		return hostProfile{}, err
	}
	if err := validateProfile(p); err != nil {
		return hostProfile{}, err
	}
	return p, nil
}

func validateProfile(p hostProfile) error {
	if p.V != 1 || !validToken(p.Host) {
		return errors.New("profile rejected")
	}
	if !hashPattern.MatchString(p.PolicyHash) || !hashPattern.MatchString(p.AdminKeysHash) {
		return errors.New("profile rejected")
	}
	for _, list := range [][]string{p.Users, p.Listeners, p.Packages, p.Sysctls, p.Units} {
		if err := validList(list); err != nil {
			return err
		}
	}
	return nil
}

func validToken(s string) bool {
	if s == "" || strings.ContainsAny(s, ", \n\x00=") {
		return false
	}
	return true
}

func validList(items []string) error {
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		if !validToken(item) {
			return errors.New("profile rejected")
		}
		if _, ok := seen[item]; ok {
			return errors.New("profile rejected")
		}
		seen[item] = struct{}{}
	}
	return nil
}

func looksSigned(body []byte) bool {
	text := string(body)
	if strings.Contains(text, " ") || strings.Contains(text, "\n") || strings.Contains(text, "{") {
		var env signedEnvelope
		if err := unmarshalStrict(body, &env); err != nil {
			return false
		}
		return env.Payload != "" && len(env.Sigs) > 0
	}
	parts := strings.Split(text, ".")
	return len(parts) == 3 && parts[0] != "" && parts[1] != "" && parts[2] != ""
}

func checkHostID(host string, require bool) error {
	if host == "" {
		return errProfileRejected
	}
	env := os.Getenv("ADSSH_HOST_ID")
	if require {
		if env == "" || env != host {
			return errProfileRejected
		}
		return nil
	}
	if env != "" && env != host {
		return errProfileRejected
	}
	return nil
}

func needsTwo(installed, candidate hostProfile, exists bool) bool {
	if !exists {
		return false
	}
	return installed.PolicyHash != candidate.PolicyHash || installed.AdminKeysHash != candidate.AdminKeysHash
}

func subset(overlay, installed []string) bool {
	have := make(map[string]struct{}, len(installed))
	for _, item := range installed {
		have[item] = struct{}{}
	}
	for _, item := range overlay {
		if _, ok := have[item]; !ok {
			return false
		}
	}
	return true
}

func narrowOf(overlay, installed hostProfile) bool {
	if overlay.PolicyHash != installed.PolicyHash || overlay.AdminKeysHash != installed.AdminKeysHash {
		return false
	}
	return subset(overlay.Users, installed.Users) &&
		subset(overlay.Listeners, installed.Listeners) &&
		subset(overlay.Packages, installed.Packages) &&
		subset(overlay.Sysctls, installed.Sysctls) &&
		subset(overlay.Units, installed.Units)
}

func formatProfile(p hostProfile) string {
	return fmt.Sprintf("host=%s\nusers=%s\nlisteners=%s\npackages=%s\nsysctls=%s\nunits=%s\npolicy=%s\nadminkeys=%s\n",
		p.Host,
		strings.Join(p.Users, ","),
		strings.Join(p.Listeners, ","),
		strings.Join(p.Packages, ","),
		strings.Join(p.Sysctls, ","),
		strings.Join(p.Units, ","),
		p.PolicyHash,
		p.AdminKeysHash,
	)
}

func profileLog(prefix string, p hostProfile) string {
	return fmt.Sprintf("%s host=%s users=%s units=%s policy=%s adminkeys=%s",
		prefix, p.Host, strings.Join(p.Users, ","), strings.Join(p.Units, ","), p.PolicyHash, p.AdminKeysHash)
}

func hostProfilePath() string { return os.Getenv("ADSSH_HOST_PROFILE") }

func hostPrevPath() string { return os.Getenv("ADSSH_HOST_PROFILE_PREV") }

func hostKeysPath() string { return os.Getenv("ADSSH_HOST_PROFILE_KEYS") }

func hostNarrowPath() string {
	if v := os.Getenv("ADSSH_HOST_PROFILE_NARROW"); v != "" {
		return v
	}
	base := hostProfilePath()
	if base == "" {
		return ""
	}
	return base + ".narrow"
}

func readOwnerOnly(path string, max int64) ([]byte, error) {
	f, info, err := safefile.Open(nil, path)
	if err != nil {
		return nil, err
	}
	body, rerr := func() ([]byte, error) {
		if info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("file is not owner-only")
		}
		return safefile.ReadAll(f, info, max)
	}()
	cerr := f.Close()
	if rerr != nil {
		if rerr.Error() == "file is not owner-only" && cerr != nil {
			return nil, fmt.Errorf("file is not owner-only: %w", cerr)
		}
		return nil, rerr
	}
	if cerr != nil {
		return nil, cerr
	}
	return body, nil
}

func readCandidate(path string) ([]byte, error) {
	f, info, err := safefile.Open(nil, path)
	if err != nil {
		return nil, err
	}
	body, rerr := safefile.ReadAll(f, info, envelopeBytesMax)
	cerr := f.Close()
	if rerr != nil {
		return nil, rerr
	}
	if cerr != nil {
		return nil, cerr
	}
	return body, nil
}

func writePrivate(path string, raw []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".host-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		cerr := tmp.Close()
		rerr := os.Remove(tmpName)
		return errors.Join(err, cerr, rerr)
	}
	if err := tmp.Close(); err != nil {
		return errors.Join(err, os.Remove(tmpName))
	}
	if err := os.Rename(tmpName, path); err != nil {
		return errors.Join(err, os.Remove(tmpName))
	}
	if err := hostChmod(path, 0o600); err != nil {
		rerr := os.Remove(path)
		if rerr != nil {
			return errors.Join(chmodError{err: err}, rerr)
		}
		return chmodError{err: err}
	}
	return nil
}

func mapHostWrite(err error) error {
	if err == nil {
		return nil
	}
	var ce chmodError
	if errors.As(err, &ce) {
		return err
	}
	return errProfileRejected
}

func readInstalledSigned() (hostProfile, error) {
	body, err := readOwnerOnly(hostProfilePath(), envelopeBytesMax)
	if err != nil {
		if os.IsNotExist(err) {
			return hostProfile{}, errProfileWiden
		}
		return hostProfile{}, errProfileRejected
	}
	if !looksSigned(body) {
		return hostProfile{}, errProfileRejected
	}
	keys, err := loadEd25519Keys(hostKeysPath())
	if err != nil {
		return hostProfile{}, errProfileRejected
	}
	p, _, err := parseSigned(body, keys)
	if err != nil {
		return hostProfile{}, errProfileRejected
	}
	return p, nil
}

func applyNarrow(installed hostProfile) (hostProfile, error) {
	path := hostNarrowPath()
	if path == "" {
		return installed, nil
	}
	body, err := readCandidate(path)
	if err != nil {
		if os.IsNotExist(err) {
			return installed, nil
		}
		return hostProfile{}, errProfileRejected
	}
	if looksSigned(body) {
		return hostProfile{}, errProfileRejected
	}
	overlay, err := parseUnsigned(body)
	if err != nil {
		return hostProfile{}, errProfileRejected
	}
	if overlay.Host != installed.Host || !narrowOf(overlay, installed) {
		return hostProfile{}, errProfileRejected
	}
	return overlay, nil
}

func init() {
	Register(hostBinary{})
}
