//go:build ee

// Threats: do is one shot on a child credential. The parent euid is never
// changed and a shell argv is refused. An agent cannot run do. Quarantine
// and recovery refuse it before a session lookup. The child argv is audited
// and authorized before exec. A failed audit does not exec. A numeric name,
// or a name containing '/', NUL, space, newline, or '=', is refused before
// lookup and before the euid check.
// Non-goals: do is not a root shell and does not Setuid the parent.

package security

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path"
	"strconv"
	"strings"
	"syscall"
)

type doUser struct {
	Name string
	Uid  string
	Gid  string
	Home string
}

var (
	doRun    func(ctx context.Context, argv []string, env []string, cred *syscall.Credential) (string, int, error)
	doEuid   func() int
	doLookup func(name string) (doUser, error)
)

type doBinary struct{}

func (doBinary) Name() string        { return "do" }
func (doBinary) Description() string { return "One-shot credentialed command" }
func (doBinary) Usage() string       { return "do: usage: do --user NAME --reason TEXT -- argv" }

func (doBinary) Run(ctx context.Context, args []string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if helpArgs(args) {
		return writeOut(ctx, doBinary{}.Usage())
	}
	userName, reason, argv, err := parseDo(args)
	if err != nil {
		return err
	}
	if inRecover(ctx) || quarantineActive() {
		return errors.New("do: refused")
	}
	sid, sess, err := requireSession(ctx, "do")
	if err != nil {
		return err
	}
	if sess.ManagedAgent() != nil {
		return errors.New("do: agents cannot run do")
	}
	if err := refuseDoUserName(userName); err != nil {
		return err
	}
	euid := os.Geteuid
	if doEuid != nil {
		euid = doEuid
	}
	if euid() != 0 {
		return errors.New("do: euid is not 0")
	}
	lookup := defaultDoLookup
	if doLookup != nil {
		lookup = doLookup
	}
	account, err := lookup(userName)
	if err != nil {
		return errors.New("do: user refused")
	}
	uid, gid, err := acceptDoAccount(account)
	if err != nil {
		return err
	}
	if err := refuseDoShell(argv[0]); err != nil {
		return err
	}
	eng := engineFromContext(ctx)
	event := fmt.Sprintf("DO user=%s reason=%s argv=%s", account.Name, reason, strings.Join(argv, " "))
	if err := eng.LogEvent(event); err != nil {
		return fmt.Errorf("adssh: audit log failed: %w", err)
	}
	if err := eng.AuthorizeCommand(argv, sid); err != nil {
		return err
	}
	run := doRun
	if run == nil {
		run = func(ctx context.Context, argv []string, env []string, cred *syscall.Credential) (string, int, error) {
			return runLimited(ctx, argv, env, cred)
		}
	}
	text, code, err := run(ctx, argv, doChildEnv(account), &syscall.Credential{Uid: uid, Gid: gid, NoSetGroups: true})
	if err != nil {
		return errors.New("do: unavailable")
	}
	if code != 0 {
		if werr := writeOut(ctx, text); werr != nil {
			return werr
		}
		return fmt.Errorf("do: exit %d", code)
	}
	return writeOut(ctx, text)
}

func parseDo(args []string) (userName, reason string, argv []string, err error) {
	usage := errors.New("do: usage: do --user NAME --reason TEXT -- argv")
	if len(args) < 2 {
		return "", "", nil, usage
	}
	i := 1
	if args[i] == "--" {
		if i+1 >= len(args) || (args[i+1] != "--user" && args[i+1] != "--reason") {
			return "", "", nil, usage
		}
		i++
	}
	var gotUser, gotReason bool
	for i < len(args) {
		if args[i] == "--" {
			argv = append([]string(nil), args[i+1:]...)
			break
		}
		if i+1 >= len(args) {
			return "", "", nil, usage
		}
		switch args[i] {
		case "--user":
			if gotUser {
				return "", "", nil, usage
			}
			userName = args[i+1]
			gotUser = true
		case "--reason":
			if gotReason {
				return "", "", nil, usage
			}
			reason = args[i+1]
			gotReason = true
		default:
			return "", "", nil, usage
		}
		i += 2
	}
	if !gotUser || !gotReason || userName == "" || reason == "" || len(argv) == 0 || argv[0] == "" {
		return "", "", nil, usage
	}
	if strings.ContainsAny(reason, "\x00\n=") {
		return "", "", nil, usage
	}
	for _, a := range argv {
		if strings.ContainsAny(a, "\x00\n") {
			return "", "", nil, usage
		}
	}
	return userName, reason, argv, nil
}

func refuseDoUserName(name string) error {
	if name == "" || numericName.MatchString(name) || strings.ContainsAny(name, "/\x00 \n=") {
		return errors.New("do: user refused")
	}
	return nil
}

func acceptDoAccount(u doUser) (uint32, uint32, error) {
	if u.Name == "" || strings.ContainsAny(u.Name, "\x00\n=") || strings.ContainsAny(u.Home, "\x00\n=") {
		return 0, 0, errors.New("do: user refused")
	}
	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, 0, errors.New("do: user refused")
	}
	gid64, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return 0, 0, errors.New("do: user refused")
	}
	return uint32(uid64), uint32(gid64), nil
}

func refuseDoShell(argv0 string) error {
	switch path.Base(argv0) {
	case "bash", "sh", "zsh", "dash", "fish", "su":
		return errors.New("do: shell is refused")
	default:
		return nil
	}
}

func defaultDoLookup(name string) (doUser, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return doUser{}, err
	}
	return doUser{Name: u.Username, Uid: u.Uid, Gid: u.Gid, Home: u.HomeDir}, nil
}

func doChildEnv(u doUser) []string {
	pathVal := os.Getenv("PATH")
	if pathVal == "" {
		pathVal = "/usr/bin:/bin"
	}
	out := []string{
		"PATH=" + pathVal,
		"HOME=" + u.Home,
		"USER=" + u.Name,
		"LOGNAME=" + u.Name,
	}
	for _, name := range []string{"LANG", "LC_ALL", "TZ", "TERM"} {
		v, ok := os.LookupEnv(name)
		if ok && v != "" {
			out = append(out, name+"="+v)
		}
	}
	return out
}

func init() { Register(doBinary{}) }
