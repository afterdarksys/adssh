//go:build ee

package security

import (
	"strings"
	"testing"
)

func TestRemoteGateProcessDeniesLocalPolicy(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte("package adssh\nauthz := {\"allow\": true}\n")})
	if err != nil {
		t.Fatal(err)
	}
	// Local process: an allow-all policy allows.
	if ok, _, err := eng.EvaluatePolicy(PolicyContext{User: "alice", Command: "ls"}); err != nil || !ok {
		t.Fatalf("local evaluate = %v %v", ok, err)
	}
	gw := GatewayPolicyRequest{SessionID: "ssh-child", User: "alice", Action: "connect", TargetHost: "127.0.0.1", TargetPort: 22}
	if err := eng.AuthorizeGateway(gw); err != nil {
		t.Fatalf("local gateway: %v", err)
	}

	rec := installRemoteGateProcess(t)
	const want = "policy is evaluated by the listener; not available in this process"
	if ok, _, err := eng.EvaluatePolicy(PolicyContext{User: "alice", Command: "ls"}); ok || err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("remote evaluate = %v %v", ok, err)
	}
	if ok, _, err := EvaluatePolicy(PolicyContext{User: "alice", Command: "ls"}); ok || err == nil {
		t.Fatalf("package evaluate = %v %v", ok, err)
	}
	if err := eng.AuthorizeGateway(gw); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("remote gateway = %v", err)
	}
	exp, err := eng.ExplainCommand("ssh-child", []string{"rm"})
	if err != nil {
		t.Fatal(err)
	}
	if exp.Outcome != "denied" {
		t.Fatalf("explain outcome = %q", exp.Outcome)
	}
	found := false
	for _, st := range exp.Stages {
		if st.Name == "policy" && st.Status == "denied" && strings.Contains(st.Reason, want) {
			found = true
		}
	}
	if !found {
		t.Fatalf("explain stages = %#v", exp.Stages)
	}
	// A governed Starlark operation is authorized through the remote gate,
	// not against the local engine.
	if err := eng.AuthorizeCommand([]string{"starlark.aws.ec2.list_instances"}, "ssh-child"); err != nil {
		t.Fatal(err)
	}
	if !rec.saw("starlark.aws.ec2.list_instances") {
		t.Fatal("starlark operation did not reach the remote gate")
	}
}
