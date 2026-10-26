//go:build ee

// Threats: raw admin names (sudo, systemctl, journalctl, apt, apt-get) are
// not a root shell. The rewrite runs before the gate, so the gate sees the
// governed verb. Quarantine and recovery refuse mutation. A nil context does
// not panic. Output from a governed child is capped and timed out.
// Non-goals: this file does not Setuid the parent, does not start sshd, and
// does not treat a lease id as authorization.

package security

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
	"mvdan.cc/sh/v3/interp"
)

const (
	adminOutputCap = 64 * 1024
	adminTimeout   = 30 * time.Second
)

var (
	unitNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@-]{0,255}$`)
	hashPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{0,128}$`)
	numericName     = regexp.MustCompile(`^[0-9]+$`)
)

var rawAdminNames = map[string]struct{}{
	"sudo":       {},
	"systemctl":  {},
	"journalctl": {},
	"apt":        {},
	"apt-get":    {},
}

type recoverCtxKey struct{}

// WithRecover marks ctx as the recovery menu. A nil context becomes Background.
func WithRecover(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, recoverCtxKey{}, true)
}

func inRecover(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(recoverCtxKey{}).(bool)
	return v
}

func init() {
	adminPlaneMu.Lock()
	adminPlaneBlocked = func(ctx context.Context) bool {
		return inRecover(ctx) || quarantineActive()
	}
	adminPlaneMu.Unlock()
	if err := SetAdminPlane(rewriteAdminPlane, adminPlaneCheck); err != nil {
		panic(err)
	}
}

func adminPlaneCheck(e *Engine, ctx context.Context, sessionID string, args []string) error {
	if len(args) > 0 {
		if _, ok := rawAdminNames[path.Base(args[0])]; ok {
			return errors.New("admin plane: raw admin name refused")
		}
	}
	if quarantineActive() && !quarantineAllows(args) {
		return errors.New("admin plane: quarantine")
	}
	if len(args) == 0 {
		return nil
	}
	return chargeAgentCommand(sessionID, path.Base(args[0]))
}

func rewriteAdminPlane(args []string) ([]string, string, error) {
	if len(args) == 0 {
		return args, "", nil
	}
	switch path.Base(args[0]) {
	case "sudo":
		return rewriteSudo(args)
	case "systemctl":
		return rewriteSystemctl(args)
	case "journalctl":
		return rewriteJournalctl(args)
	case "apt", "apt-get":
		return nil, "", errors.New("alias: apt is refused; the governed verb is package")
	default:
		return args, "", nil
	}
}

func rewriteSudo(args []string) ([]string, string, error) {
	found := false
	for _, a := range args[1:] {
		if a == "--" {
			found = true
			break
		}
	}
	if !found {
		return nil, "", errors.New("alias: sudo is refused; the governed verb is do")
	}
	out := append([]string{"do"}, args[1:]...)
	return out, "alias: sudo → do", nil
}

func rewriteSystemctl(args []string) ([]string, string, error) {
	if len(args) == 3 {
		switch args[1] {
		case "status", "restart", "stop":
			if unitNamePattern.MatchString(args[2]) {
				return []string{"unit", args[1], args[2]}, "alias: systemctl → unit", nil
			}
		}
	}
	return nil, "", errors.New("alias: systemctl is refused; the governed verb is unit")
}

func rewriteJournalctl(args []string) ([]string, string, error) {
	name, ok := journalctlUnit(args)
	if !ok || !unitNamePattern.MatchString(name) {
		return nil, "", errors.New("alias: journalctl is refused; the governed verb is unit logs NAME")
	}
	return []string{"unit", "logs", name}, "alias: journalctl → unit logs", nil
}

func journalctlUnit(args []string) (string, bool) {
	switch len(args) {
	case 3:
		if args[1] == "-u" {
			return args[2], true
		}
	case 4:
		if args[1] == "-u" && args[3] == "--no-pager" {
			return args[2], true
		}
		if args[1] == "--no-pager" && args[2] == "-u" {
			return args[3], true
		}
	}
	return "", false
}

// writeOut prints text to the handler stdout. A nil context returns nil.
// A missing handler is recovered and the text is discarded. A trailing
// newline is added only when one is missing.
func writeOut(ctx context.Context, text string) (err error) {
	if ctx == nil || text == "" {
		return nil
	}
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	defer func() {
		if recover() != nil {
			_, _ = io.WriteString(io.Discard, text)
			err = nil
		}
	}()
	hc := interp.HandlerCtx(ctx)
	w := hc.Stdout
	if w == nil {
		w = io.Discard
	}
	_, err = io.WriteString(w, text)
	return err
}

type capBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (c *capBuf) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(p)
	if c.buf.Len() < c.max {
		remain := c.max - c.buf.Len()
		chunk := p
		if len(chunk) > remain {
			chunk = chunk[:remain]
		}
		if _, err := c.buf.Write(chunk); err != nil {
			return 0, err
		}
	}
	return n, nil
}

func (c *capBuf) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// runLimited runs argv with a 30s timeout and a 64 KiB combined output cap.
// A non-nil credential is applied only to the child.
func runLimited(ctx context.Context, argv []string, env []string, cred *syscall.Credential) (string, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(argv) == 0 || argv[0] == "" {
		return "", 0, errors.New("empty argv")
	}
	cctx, cancel := context.WithTimeout(ctx, adminTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, argv[0], argv[1:]...)
	cmd.Env = env
	if cred != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	buf := &capBuf{max: adminOutputCap}
	cmd.Stdout = buf
	cmd.Stderr = buf
	err := cmd.Run()
	text := buf.String()
	if err == nil {
		return text, 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return text, ee.ExitCode(), nil
	}
	return text, 0, err
}

// observeEnv is the cleaned environment for unit, net, disk, and journal.
// ADSSH_* never crosses. An empty PATH becomes the default search path.
func observeEnv() []string {
	var out []string
	for _, name := range []string{"PATH", "LANG", "LC_ALL", "TZ", "TERM"} {
		if strings.HasPrefix(name, "ADSSH_") {
			continue
		}
		v, ok := os.LookupEnv(name)
		if !ok || v == "" || strings.HasPrefix(name, "ADSSH_") {
			continue
		}
		out = append(out, name+"="+v)
	}
	hasPath := false
	for _, item := range out {
		if strings.HasPrefix(item, "PATH=") {
			hasPath = true
			break
		}
	}
	if !hasPath {
		out = append(out, "PATH=/usr/bin:/bin")
	}
	return out
}

func requireSession(ctx context.Context, verb string) (string, *sys.Session, error) {
	sid := SessionIDFromContext(ctx)
	if sid == "" {
		return "", nil, errors.New(verb + ": requires a session")
	}
	sess := sys.GetSession(sid)
	if sess == nil {
		return "", nil, errors.New(verb + ": requires a session")
	}
	return sid, sess, nil
}

func helpArgs(args []string) bool {
	return len(args) > 1 && (args[1] == "--help" || args[1] == "help")
}
