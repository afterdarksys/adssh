//go:build ee

// Threats: posture, net, and disk only observe. A failed or empty listen
// probe is reported open. A non-loopback listener is open. They do not
// start sshd, do not change listeners, and do not authorize a command.
// Quarantine allows these verbs.
// Non-goals: this file does not install a firewall and does not treat a
// lease id as authorization.

package security

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var (
	netRun  func(ctx context.Context, argv []string) (string, int, error)
	netShow func(ctx context.Context) (string, int, error)
	diskRun func(ctx context.Context, argv []string) (string, int, error)
)

type netBinary struct{}

func (netBinary) Name() string        { return "net" }
func (netBinary) Description() string { return "Listening sockets" }
func (netBinary) Usage() string       { return "net: usage: net" }

func (n netBinary) Run(ctx context.Context, args []string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if helpArgs(args) {
		return writeOut(ctx, n.Usage())
	}
	if len(args) != 1 {
		return errors.New("net: usage: net")
	}
	if _, _, err := requireSession(ctx, "net"); err != nil {
		return err
	}
	if netRun != nil {
		text, code, err := netRun(ctx, []string{"net"})
		if err != nil {
			return errors.New("net: unavailable")
		}
		if werr := writeOut(ctx, text); werr != nil {
			return werr
		}
		if code != 0 {
			return nil
		}
		return nil
	}
	text, code, err := runLimited(ctx, []string{"netstat", "-an"}, observeEnv(), nil)
	if err != nil {
		return errors.New("net: unavailable")
	}
	if code != 0 {
		return writeOut(ctx, text)
	}
	return writeOut(ctx, listenLines(text))
}

type diskBinary struct{}

func (diskBinary) Name() string        { return "disk" }
func (diskBinary) Description() string { return "Disk space" }
func (diskBinary) Usage() string       { return "disk: usage: disk" }

func (d diskBinary) Run(ctx context.Context, args []string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if helpArgs(args) {
		return writeOut(ctx, d.Usage())
	}
	if len(args) != 1 {
		return errors.New("disk: usage: disk")
	}
	if _, _, err := requireSession(ctx, "disk"); err != nil {
		return err
	}
	argv := []string{"df", "-P"}
	var text string
	var code int
	var err error
	if diskRun != nil {
		text, code, err = diskRun(ctx, argv)
	} else {
		text, code, err = runLimited(ctx, argv, observeEnv(), nil)
	}
	if err != nil {
		return errors.New("disk: unavailable")
	}
	if werr := writeOut(ctx, text); werr != nil {
		return werr
	}
	if code != 0 {
		return nil
	}
	return nil
}

type postureBinary struct{}

func (postureBinary) Name() string        { return "posture" }
func (postureBinary) Description() string { return "Listener posture" }
func (postureBinary) Usage() string       { return "posture: usage: posture" }

func (p postureBinary) Run(ctx context.Context, args []string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if helpArgs(args) {
		return writeOut(ctx, p.Usage())
	}
	if len(args) != 1 {
		return errors.New("posture: usage: posture")
	}
	if _, _, err := requireSession(ctx, "posture"); err != nil {
		return err
	}
	ssh, admin, listeners := "open", "open", "open"
	proof, ok := postureProbe(ctx)
	if ok && strings.TrimSpace(proof) != "" {
		ssh, admin, listeners = bucketListen(proof)
	}
	seq := postureChainSeq(ctx)
	return writeOut(ctx, fmt.Sprintf("ssh=%s admin=%s listeners=%s chain=%d\n", ssh, admin, listeners, seq))
}

func postureProbe(ctx context.Context) (string, bool) {
	if netShow != nil {
		text, code, err := netShow(ctx)
		if err != nil || code != 0 {
			return "", false
		}
		if strings.Contains(text, "LISTEN") {
			return listenLines(text), true
		}
		return text, true
	}
	text, code, err := runLimited(ctx, []string{"netstat", "-an"}, observeEnv(), nil)
	if err != nil || code != 0 {
		return "", false
	}
	return listenLines(text), true
}

func postureChainSeq(ctx context.Context) int64 {
	path, key, ok := engineFromContext(ctx).chainMaterial()
	if !ok {
		return 0
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	_, next, err := readLastChainLine(path, key)
	if err != nil {
		return 0
	}
	return next
}

func bucketListen(proof string) (ssh, admin, listeners string) {
	adminPort := adminListenPort()
	var sshLines, adminLines, all []string
	for _, line := range strings.Split(proof, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "listen none" {
			continue
		}
		all = append(all, line)
		if !strings.HasPrefix(line, "listen ") {
			continue
		}
		port := listenPort(line)
		if port == "22" {
			sshLines = append(sshLines, line)
		}
		if adminPort != "" && port == adminPort {
			adminLines = append(adminLines, line)
		}
	}
	return closedWord(sshLines), closedWord(adminLines), closedWord(all)
}

func closedWord(lines []string) string {
	if len(lines) == 0 {
		return "closed"
	}
	if postureClosed(strings.Join(lines, "\n")) {
		return "closed"
	}
	return "open"
}

func postureClosed(proof string) bool {
	proof = strings.TrimSpace(proof)
	if proof == "" {
		return false
	}
	for _, line := range strings.Split(proof, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !closedListenLine(line) {
			return false
		}
	}
	return true
}

func closedListenLine(line string) bool {
	if line == "listen none" {
		return true
	}
	rest, ok := strings.CutPrefix(line, "listen ")
	if !ok {
		return false
	}
	var port string
	switch {
	case strings.HasPrefix(rest, "127.0.0.1:"):
		port = strings.TrimPrefix(rest, "127.0.0.1:")
	case strings.HasPrefix(rest, "[::1]:"):
		port = strings.TrimPrefix(rest, "[::1]:")
	default:
		return false
	}
	return numericPort(port)
}

func listenPort(line string) string {
	rest, ok := strings.CutPrefix(line, "listen ")
	if !ok || rest == "none" || rest == "open" {
		return ""
	}
	i := strings.LastIndex(rest, ":")
	if i < 0 {
		return ""
	}
	port := rest[i+1:]
	if !numericPort(port) {
		return ""
	}
	return port
}

func adminListenPort() string {
	spec := os.Getenv("ADSSH_ADMIN_LISTEN")
	i := strings.LastIndex(spec, ":")
	if i < 0 {
		return ""
	}
	port := spec[i+1:]
	if !numericPort(port) {
		return ""
	}
	return port
}

func listenLines(text string) string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[len(fields)-1] != "LISTEN" {
			continue
		}
		lines = append(lines, splitListen(fields[len(fields)-3]))
	}
	if len(lines) == 0 {
		return "listen none"
	}
	return strings.Join(lines, "\n")
}

func splitListen(local string) string {
	host, port, ok := splitHostPort(local)
	if !ok || !numericPort(port) {
		return "listen open"
	}
	switch host {
	case "*", "0.0.0.0":
		return "listen 0.0.0.0:" + port
	case "::", "":
		return "listen [::]:" + port
	case "::1", "[::1]":
		return "listen [::1]:" + port
	case "[::]":
		return "listen [::]:" + port
	default:
		return "listen " + host + ":" + port
	}
}

func splitHostPort(local string) (host, port string, ok bool) {
	// Netstat prints IPv6 locals as ::1.22 and ::.22. A colon split would
	// treat the address colons as the port separator, so a numeric
	// dot-suffix wins first. Bracket and IPv4 colon forms fall through.
	if i := strings.LastIndex(local, "."); i >= 0 {
		host, port = local[:i], local[i+1:]
		if numericPort(port) {
			return host, port, true
		}
	}
	if i := strings.LastIndex(local, ":"); i >= 0 {
		return local[:i], local[i+1:], true
	}
	return "", "", false
}

func numericPort(port string) bool {
	if port == "" || !numericName.MatchString(port) {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 0 && n <= 65535
}

func init() {
	Register(postureBinary{})
	Register(netBinary{})
	Register(diskBinary{})
}
