//go:build ee

package main

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/afterdarksys/adssh/security"
)

// The listener's monitor hook runs elevate in the listener's session over a
// Run frame, and the next Authorize sees the role.
func TestSSHMonitorServerRunsElevateInListener(t *testing.T) {
	eng, err := security.NewEngine(security.EngineConfig{PolicySource: []byte(`package adssh.authz
default allow = false
allow { input.command != "deploy" }
allow { input.command == "deploy"; input.elevation.role == "ops" }
`)})
	if err != nil {
		t.Fatal(err)
	}
	id := "main-run-elevate"
	sess := &sys.Session{ID: id, User: "bob"}
	if err := sys.RegisterSession(sess); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(id) })

	server, client := net.Pipe()
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		<-done
	})
	go func() {
		defer close(done)
		sshMonitorServer(eng)(server, id)
	}()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	mc := sys.NewMonitorClient(client)
	if err := mc.Authorize([]string{"deploy"}); err == nil {
		t.Fatal("deploy allowed before elevation")
	}
	var stdout, stderr bytes.Buffer
	code, err := mc.Run([]string{"elevate", "request", "ops", "--reason", "x"}, sys.MonitorStdinNone, nil, &stdout, &stderr)
	if err != nil || code != 0 || !strings.Contains(stdout.String(), "elevate: role=ops") {
		t.Fatalf("code=%d err=%v stdout=%q stderr=%q", code, err, stdout.String(), stderr.String())
	}
	if e := sess.ActiveElevation(); e == nil || e.Role != "ops" {
		t.Fatalf("listener elevation = %+v", e)
	}
	if err := mc.Authorize([]string{"deploy"}); err != nil {
		t.Fatalf("deploy after elevation: %v", err)
	}
	// Interactive vbins stay refused over Run.
	_, err = mc.Run([]string{"mirror", "console", "x"}, sys.MonitorStdinNone, nil, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "not available in an SSH session") {
		t.Fatalf("mirror console: %v", err)
	}
}
