package security

// Threats:
//   Proves the shell OPEN handler cannot be used as an unaudited egress channel
//   (SEC-1). `/dev/tcp/host/port` and `/dev/udp/host/port` redirections are
//   policy-gated as a command named /dev/tcp (or /dev/udp) with args
//   [host, port], audited on both allow and deny, refused in restricted mode,
//   and malformed device paths are rejected before any gate or dial. Ordinary
//   file redirection must keep working.
//
//   NOT covered: DNS resolution of the host name (resolution happens inside
//   Dial after policy sees the name), /dev/fd, and process substitution.

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

const openAllowAll = `package adssh.authz
default allow = true`

const openDenyAll = `package adssh.authz
default allow = false
deny_reason = "egress denied"`

func openHostPolicy(network string) string {
	return fmt.Sprintf(`package adssh.authz
default allow = false
allow { input.command == "/dev/%s"; input.args[0] == "127.0.0.1" }`, network)
}

// newOpenEngine builds an isolated engine with an inline policy and its own
// flat audit log, returning the engine and the audit log path.
func newOpenEngine(t *testing.T, policy string) (*Engine, string) {
	t.Helper()
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(policy), AuditLogPath: auditPath})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng, auditPath
}

// runOpenShell runs src through a runner whose open handler is the engine's
// gated OpenHandlerSession, in the given working directory.
func runOpenShell(t *testing.T, eng *Engine, restricted bool, dir, src string) error {
	t.Helper()
	var stdout, stderr bytes.Buffer
	state := &SessionState{Restricted: restricted, Globals: starlark.StringDict{}}
	r, err := interp.New(
		interp.StdIO(strings.NewReader(""), &stdout, &stderr),
		interp.Dir(dir),
		interp.OpenHandler(eng.OpenHandlerSession(state)),
	)
	if err != nil {
		t.Fatalf("interp.New: %v", err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader(src), "test.sh")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return r.Run(context.Background(), file)
}

func readAudit(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read audit log: %v", err)
	}
	return string(data)
}

// tcpSink accepts connections on a loopback port and reports what arrives.
type tcpSink struct {
	ln   net.Listener
	port string
	got  chan string
}

func newTCPSink(t *testing.T) *tcpSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &tcpSink{ln: ln, port: strconv.Itoa(ln.Addr().(*net.TCPAddr).Port), got: make(chan string, 4)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				var buf bytes.Buffer
				_, _ = buf.ReadFrom(c)
				s.got <- buf.String()
			}(c)
		}
	}()
	return s
}

// expectNothing asserts no connection delivered data within a short window.
func (s *tcpSink) expectNothing(t *testing.T) {
	t.Helper()
	select {
	case data := <-s.got:
		t.Fatalf("SECURITY: denied redirection reached the listener: %q", data)
	case <-time.After(200 * time.Millisecond):
	}
}

func (s *tcpSink) expect(t *testing.T, want string) {
	t.Helper()
	select {
	case data := <-s.got:
		if data != want {
			t.Fatalf("listener got %q, want %q", data, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for bytes at the listener")
	}
}

type udpSink struct {
	pc   net.PacketConn
	port string
}

func newUDPSink(t *testing.T) *udpSink {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return &udpSink{pc: pc, port: strconv.Itoa(pc.LocalAddr().(*net.UDPAddr).Port)}
}

func (s *udpSink) read(wait time.Duration) (string, bool) {
	buf := make([]byte, 1024)
	_ = s.pc.SetReadDeadline(time.Now().Add(wait))
	n, _, err := s.pc.ReadFrom(buf)
	if err != nil {
		return "", false
	}
	return string(buf[:n]), true
}

func TestOpenHandler_TCP_DenyAll_RefusedAndAudited(t *testing.T) {
	sink := newTCPSink(t)
	eng, audit := newOpenEngine(t, openDenyAll)

	err := runOpenShell(t, eng, false, t.TempDir(), "echo hi > /dev/tcp/127.0.0.1/"+sink.port)
	if err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("expected policy denial, got: %v", err)
	}
	sink.expectNothing(t)

	log := readAudit(t, audit)
	cmd := "/dev/tcp 127.0.0.1 " + sink.port
	if !strings.Contains(log, "[BASH] "+cmd+"\n") {
		t.Errorf("audit log missing BASH line for %q:\n%s", cmd, log)
	}
	if !strings.Contains(log, "command="+cmd+" allowed=false") {
		t.Errorf("audit log missing deny decision for %q:\n%s", cmd, log)
	}
}

func TestOpenHandler_TCP_HostPolicy_AllowsMatchingHost(t *testing.T) {
	sink := newTCPSink(t)
	eng, audit := newOpenEngine(t, openHostPolicy("tcp"))

	if err := runOpenShell(t, eng, false, t.TempDir(), "echo hi > /dev/tcp/127.0.0.1/"+sink.port); err != nil {
		t.Fatalf("allowed redirection failed: %v", err)
	}
	sink.expect(t, "hi\n")

	log := readAudit(t, audit)
	if !strings.Contains(log, "command=/dev/tcp 127.0.0.1 "+sink.port+" allowed=true") {
		t.Errorf("audit log missing allow decision:\n%s", log)
	}
}

func TestOpenHandler_TCP_HostPolicy_DeniesOtherHost(t *testing.T) {
	sink := newTCPSink(t)
	eng, audit := newOpenEngine(t, openHostPolicy("tcp"))

	// localhost resolves to the same listener, but policy sees the name.
	err := runOpenShell(t, eng, false, t.TempDir(), "echo hi > /dev/tcp/localhost/"+sink.port)
	if err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("expected policy denial for other host, got: %v", err)
	}
	sink.expectNothing(t)
	if log := readAudit(t, audit); !strings.Contains(log, "command=/dev/tcp localhost "+sink.port+" allowed=false") {
		t.Errorf("audit log missing deny decision:\n%s", log)
	}
}

func TestOpenHandler_TCP_Restricted_DeniedUnderAllowAll(t *testing.T) {
	sink := newTCPSink(t)
	eng, _ := newOpenEngine(t, openAllowAll)

	err := runOpenShell(t, eng, true, t.TempDir(), "echo hi > /dev/tcp/127.0.0.1/"+sink.port)
	if err == nil || !strings.Contains(err.Error(), "restricted") {
		t.Fatalf("expected restricted-mode denial, got: %v", err)
	}
	sink.expectNothing(t)
}

func TestOpenHandler_UDP_DenyAll_RefusedAndAudited(t *testing.T) {
	sink := newUDPSink(t)
	eng, audit := newOpenEngine(t, openDenyAll)

	err := runOpenShell(t, eng, false, t.TempDir(), "echo hi > /dev/udp/127.0.0.1/"+sink.port)
	if err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("expected policy denial, got: %v", err)
	}
	if data, ok := sink.read(200 * time.Millisecond); ok {
		t.Fatalf("SECURITY: denied udp redirection delivered %q", data)
	}
	log := readAudit(t, audit)
	cmd := "/dev/udp 127.0.0.1 " + sink.port
	if !strings.Contains(log, "[BASH] "+cmd+"\n") || !strings.Contains(log, "command="+cmd+" allowed=false") {
		t.Errorf("audit log missing BASH line or deny decision for %q:\n%s", cmd, log)
	}
}

func TestOpenHandler_UDP_HostPolicy_AllowsMatchingHost(t *testing.T) {
	sink := newUDPSink(t)
	eng, _ := newOpenEngine(t, openHostPolicy("udp"))

	if err := runOpenShell(t, eng, false, t.TempDir(), "printf hi > /dev/udp/127.0.0.1/"+sink.port); err != nil {
		t.Fatalf("allowed udp redirection failed: %v", err)
	}
	// printf issues a single write, so the payload is one datagram.
	data, ok := sink.read(5 * time.Second)
	if !ok || data != "hi" {
		t.Fatalf("udp listener got %q (ok=%v), want %q", data, ok, "hi")
	}
}

func TestOpenHandler_UDP_HostPolicy_DeniesOtherHost(t *testing.T) {
	sink := newUDPSink(t)
	eng, _ := newOpenEngine(t, openHostPolicy("udp"))

	err := runOpenShell(t, eng, false, t.TempDir(), "echo hi > /dev/udp/localhost/"+sink.port)
	if err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("expected policy denial for other host, got: %v", err)
	}
	if data, ok := sink.read(200 * time.Millisecond); ok {
		t.Fatalf("SECURITY: denied udp redirection delivered %q", data)
	}
}

func TestOpenHandler_UDP_Restricted_DeniedUnderAllowAll(t *testing.T) {
	sink := newUDPSink(t)
	eng, _ := newOpenEngine(t, openAllowAll)

	err := runOpenShell(t, eng, true, t.TempDir(), "echo hi > /dev/udp/127.0.0.1/"+sink.port)
	if err == nil || !strings.Contains(err.Error(), "restricted") {
		t.Fatalf("expected restricted-mode denial, got: %v", err)
	}
	if data, ok := sink.read(200 * time.Millisecond); ok {
		t.Fatalf("SECURITY: restricted udp redirection delivered %q", data)
	}
}

func TestOpenHandler_MalformedPaths_RejectedWithoutDial(t *testing.T) {
	sink := newTCPSink(t)
	p := sink.port
	cases := []string{
		"/dev/tcp/",
		"/dev/tcp/h",
		"/dev/tcp/h/0",
		"/dev/tcp/h/99999",
		"/dev/tcp/h/80/x",
		"/dev/tcp//80",
		"/dev/tcp/h/-1",
		"/dev/tcp/h/+80",
		"/dev/tcp/h/",
		"/dev/tcp/127.0.0.1/" + p + "/x",
		"/dev/tcp/127.0.0.1/" + p + "/",
		"/dev/./tcp/127.0.0.1/" + p,
		"/dev//tcp/127.0.0.1/" + p,
		"/dev/udp/",
		"/dev/udp/h/0",
		"/dev/udp/h/99999",
		"/dev/udp/h/53/x",
	}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			eng, audit := newOpenEngine(t, openAllowAll)
			err := runOpenShell(t, eng, false, t.TempDir(), "echo hi > "+path)
			if err == nil || !strings.Contains(err.Error(), "invalid network device path") {
				t.Fatalf("expected malformed-path rejection for %q, got: %v", path, err)
			}
			if log := readAudit(t, audit); strings.Contains(log, "/dev/") {
				t.Errorf("malformed path reached the gate (audited): %s", log)
			}
		})
	}
	sink.expectNothing(t)
}

func TestOpenHandler_RelativePathUnderDev_RejectedWithoutDial(t *testing.T) {
	sink := newTCPSink(t)
	eng, audit := newOpenEngine(t, openAllowAll)
	err := runOpenShell(t, eng, false, "/dev", "echo hi > tcp/127.0.0.1/"+sink.port)
	if err == nil || !strings.Contains(err.Error(), "invalid network device path") {
		t.Fatalf("expected non-canonical relative device path rejection, got: %v", err)
	}
	sink.expectNothing(t)
	if log := readAudit(t, audit); strings.Contains(log, "/dev/") {
		t.Errorf("relative device path reached the gate: %s", log)
	}
}

func TestOpenHandler_OrdinaryFileRedirection_StillWorks(t *testing.T) {
	eng, audit := newOpenEngine(t, openDenyAll)
	dir := t.TempDir()
	if err := runOpenShell(t, eng, false, dir, "echo hello > out.txt; echo again >> out.txt"); err != nil {
		t.Fatalf("file redirection failed: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "out.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello\nagain\n" {
		t.Fatalf("file content = %q", data)
	}
	if log := readAudit(t, audit); strings.Contains(log, "out.txt") {
		t.Errorf("file redirection should not hit the command gate: %s", log)
	}
}

func TestClassifyCapabilities_NetworkDevices(t *testing.T) {
	if got := ClassifyCapabilities("/dev/tcp"); strings.Join(got, ",") != "net,tcp" {
		t.Errorf("/dev/tcp capabilities = %v, want [net tcp]", got)
	}
	if got := ClassifyCapabilities("/dev/udp"); strings.Join(got, ",") != "net" {
		t.Errorf("/dev/udp capabilities = %v, want [net]", got)
	}
}

func TestOpenHandler_CapabilityPolicy_DeniesNet(t *testing.T) {
	sink := newTCPSink(t)
	eng, _ := newOpenEngine(t, `package adssh.authz
default allow = true
allow = false { input.capabilities[_] == "net" }`)
	err := runOpenShell(t, eng, false, t.TempDir(), "echo hi > /dev/tcp/127.0.0.1/"+sink.port)
	if err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("expected capability-based denial, got: %v", err)
	}
	sink.expectNothing(t)
}

// In the SSH session child fd 3 is the policy-monitor socket; an in-process
// builtin redirected to /dev/fd/3 could forge frames into it. Any descriptor
// path >= 3 is a hard deny regardless of policy or restricted mode.
func TestOpenHandler_FDRedirection_HighDescriptorsDenied(t *testing.T) {
	for _, restricted := range []bool{false, true} {
		for _, path := range []string{
			"/dev/fd/3",
			"/dev/fd/10",
			"/dev/fd/03",
			"/proc/self/fd/3",
			"/proc/thread-self/fd/4",
			"/proc/1234/fd/3",
			"/proc/self/task/1234/fd/3",
			"/dev/./fd/3",
		} {
			t.Run(fmt.Sprintf("%s/restricted=%v", path, restricted), func(t *testing.T) {
				eng, audit := newOpenEngine(t, openAllowAll)
				err := runOpenShell(t, eng, restricted, t.TempDir(), "printf forged > "+path)
				if err == nil || !strings.Contains(err.Error(), "fd redirection to descriptor") || !strings.Contains(err.Error(), "is not permitted") {
					t.Fatalf("expected fd redirection denial for %q, got: %v", path, err)
				}
				if log := readAudit(t, audit); log != "" {
					t.Errorf("fd denial must not consult the policy gate, audit log: %s", log)
				}
			})
		}
	}
}

func TestOpenHandler_FDRedirection_StdDescriptorsAllowed(t *testing.T) {
	eng, _ := newOpenEngine(t, openDenyAll)
	for _, src := range []string{
		"printf '' > /dev/fd/1",
		"printf '' > /dev/fd/2",
		"printf '' > /dev/stdout",
		"printf '' > /dev/stderr",
		"echo hi > /dev/null",
		"cat < /dev/null",
	} {
		if err := runOpenShell(t, eng, false, t.TempDir(), src); err != nil {
			t.Errorf("%q failed: %v", src, err)
		}
	}
}

// A nil engine must still gate through the default engine, never fall back to
// an ungated dial.
func TestOpenHandler_NilEngine_UsesDefaultEngineGate(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)
	if err := LoadPolicy(writePolicy(t, openDenyAll)); err != nil {
		t.Fatal(err)
	}
	sink := newTCPSink(t)
	var eng *Engine
	err := runOpenShell(t, eng, false, t.TempDir(), "echo hi > /dev/tcp/127.0.0.1/"+sink.port)
	if err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("expected default-engine policy denial, got: %v", err)
	}
	sink.expectNothing(t)
}
