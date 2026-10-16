package starlarkext

import (
	"net"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
)

// udpServer answers each datagram with reply(datagram).
func udpServer(t *testing.T, reply func([]byte) []byte) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 70000)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if out := reply(buf[:n]); out != nil {
				if _, err := conn.WriteTo(out, addr); err != nil {
					return
				}
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func TestNetDialUDPEcho(t *testing.T) {
	port := udpServer(t, func(b []byte) []byte { return append([]byte("echo:"), b...) })
	env := governedEnv(t, false)
	env["PORT"] = starlark.MakeInt(port)
	g, err := starlark.ExecFile(&starlark.Thread{Name: "t"}, "t.star", `out = net["dial_udp"]("127.0.0.1", PORT, "ping", timeout=2)`, env)
	if err != nil {
		t.Fatalf("dial_udp: %v", err)
	}
	assertStr(t, g, "out", "echo:ping")
}

func TestNetDialUDPTimeoutFailsClosed(t *testing.T) {
	port := udpServer(t, func([]byte) []byte { return nil })
	env := governedEnv(t, false)
	env["PORT"] = starlark.MakeInt(port)
	_, err := starlark.ExecFile(&starlark.Thread{Name: "t"}, "t.star", `net["dial_udp"]("127.0.0.1", PORT, "ping", timeout=1)`, env)
	if err == nil {
		t.Fatal("expected a timeout error")
	}
}

func TestNetDialUDPRejectsBadInput(t *testing.T) {
	for _, src := range []string{
		`net["dial_udp"]("127.0.0.1", 0, "x")`,
		`net["dial_udp"]("127.0.0.1", 70000, "x")`,
		`net["dial_udp"]("", 53, "x")`,
		`net["dial_udp"]("127.0.0.1", 53, "x", timeout=0)`,
		`net["dial_udp"]("127.0.0.1", 53, "x", timeout=120)`,
		`net["dial_udp"]("127.0.0.1", 53, "x" * 70000)`,
	} {
		if _, err := runScriptErr(t, false, src); err == nil {
			t.Fatalf("%s: expected an error", src)
		}
	}
}

// dial_udp is gated exactly like net.dial: a policy that denies the net
// capability denies it before any packet is sent.
func TestNetDialUDPGatedByNetCapability(t *testing.T) {
	got := make(chan struct{}, 1)
	port := udpServer(t, func([]byte) []byte { got <- struct{}{}; return []byte("x") })
	eng, err := security.NewEngine(security.EngineConfig{PolicySource: []byte(`
package adssh.authz
import future.keywords.in
default allow = true
allow = false { "net" in input.capabilities }
deny_reason = "net denied" { "net" in input.capabilities }
`)})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	env := execEnv(t, eng, false)
	env["PORT"] = starlark.MakeInt(port)
	_, err = starlark.ExecFile(&starlark.Thread{Name: "t"}, "t.star", `net["dial_udp"]("127.0.0.1", PORT, "ping", timeout=1)`, env)
	if err == nil || !strings.Contains(err.Error(), "net denied") {
		t.Fatalf("err = %v, want the net capability denial", err)
	}
	select {
	case <-got:
		t.Fatal("a packet was sent despite the denial")
	default:
	}
}
