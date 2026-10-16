package security

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func runGatewayVBin(t *testing.T, eng *Engine, args []string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	runner, err := interp.New(
		interp.StdIO(nil, &out, &errOut),
		interp.ExecHandler(func(ctx context.Context, _ []string) error {
			return eng.DispatchVBin(ctx, gatewayBinary{}, args)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader("gateway-test"), "")
	if err != nil {
		t.Fatal(err)
	}
	runErr := runner.Run(context.Background(), file)
	if runErr == nil && errOut.Len() > 0 {
		runErr = &runbookTestError{message: strings.TrimSpace(errOut.String())}
	}
	return out.String(), runErr
}

func TestGatewayStartProxiesTCPAndAuditsStop(t *testing.T) {
	target, closeTarget := startGatewayEchoServer(t)
	defer closeTarget()
	dir := t.TempDir()
	t.Setenv("ADSSH_GATEWAY_LOG", filepath.Join(dir, "gateway_connections.jsonl"))
	chainPath := filepath.Join(dir, "audit.chain")
	eng, err := NewEngine(EngineConfig{
		ChainPath:    chainPath,
		ChainKeyPath: filepath.Join(dir, "audit.key"),
		SessionID:    "gateway-test",
	})
	if err != nil {
		t.Fatal(err)
	}

	output, err := runGatewayVBin(t, eng, []string{"gateway", "start", "--listen", "127.0.0.1:0", "--target", target, "--name", "unit"})
	if err != nil {
		t.Fatal(err)
	}
	id, listen := parseGatewayStartOutput(t, output)
	conn, err := net.DialTimeout("tcp", listen, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(conn, "ping"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if line != "echo: ping\n" {
		t.Fatalf("proxied response = %q", line)
	}

	listOutput, err := runGatewayVBin(t, eng, []string{"gateway", "list"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(listOutput, id) || !strings.Contains(listOutput, target) || !strings.Contains(listOutput, `name="unit"`) {
		t.Fatalf("gateway list output = %q", listOutput)
	}
	stopOutput, err := runGatewayVBin(t, eng, []string{"gateway", "stop", id})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stopOutput, "stopped "+id) {
		t.Fatalf("stop output = %q", stopOutput)
	}
	if _, err := net.DialTimeout("tcp", listen, 150*time.Millisecond); err == nil {
		t.Fatal("gateway listener still accepted connections after stop")
	}
	chain, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(chain), "GATEWAY_START") || !strings.Contains(string(chain), "GATEWAY_STOP") {
		t.Fatalf("gateway events were not audited: %s", chain)
	}
	// The proxy writes the record when the client's connection finishes,
	// asynchronously to stop, so wait for it.
	var gatewayLog []byte
	for deadline := time.Now().Add(2 * time.Second); ; {
		gatewayLog, err = os.ReadFile(filepath.Join(dir, "gateway_connections.jsonl"))
		if err == nil && len(bytes.TrimSpace(gatewayLog)) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("gateway connection record not written: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	var record GatewayConnectionRecord
	if err := json.Unmarshal(bytes.TrimSpace(gatewayLog), &record); err != nil {
		t.Fatal(err)
	}
	if record.GatewayID != id || record.Target != target || record.BytesToTarget == 0 || record.BytesToClient == 0 || record.CloseReason == "" {
		t.Fatalf("gateway connection record = %#v", record)
	}
}

func TestGatewayDeniedByPolicyDoesNotStartListener(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(`
package adssh.authz
default allow = false
default deny_reason = "gateway blocked"
allow { input.command == "gateway"; input.args[0] == "list" }
`)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = eng.runGovernedCommand(context.Background(), "", governedCommand{
		Args: []string{"gateway", "start", "--listen", "127.0.0.1:0", "--target", "127.0.0.1:22"},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "gateway blocked") {
		t.Fatalf("expected policy denial, got %v", err)
	}
}

func TestGatewayPolicyReceivesStructuredTargetFields(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(`
package adssh.authz
default allow = false
default deny_reason = "structured gateway fields did not match"
allow {
  input.command == "gateway"
  input.gateway.action == "connect"
  input.gateway.target_host == "127.0.0.1"
  input.gateway.target_port == "2222"
  input.gateway.name == "unit"
}
`)})
	if err != nil {
		t.Fatal(err)
	}
	err = eng.AuthorizeGateway(GatewayPolicyRequest{
		Action:     "connect",
		Name:       "unit",
		TargetHost: "127.0.0.1",
		TargetPort: 2222,
	})
	if err != nil {
		t.Fatalf("structured gateway policy denied: %v", err)
	}
}

func startGatewayEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				scanner := bufio.NewScanner(conn)
				for scanner.Scan() {
					fmt.Fprintf(conn, "echo: %s\n", scanner.Text())
				}
			}(conn)
		}
	}()
	return listener.Addr().String(), func() {
		_ = listener.Close()
		<-done
	}
}

func parseGatewayStartOutput(t *testing.T, output string) (string, string) {
	t.Helper()
	fields := strings.Fields(output)
	values := map[string]string{}
	for _, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		if ok {
			values[key] = value
		}
	}
	if values["id"] == "" || values["listen"] == "" {
		t.Fatalf("could not parse gateway output: %q", output)
	}
	return values["id"], values["listen"]
}

func TestGatewayPolicyTargetIP(t *testing.T) {
	hostnameOnly, err := NewEngine(EngineConfig{PolicySource: []byte(`
package adssh.authz
default allow = false
default deny_reason = "gateway target is not allowed"
allow {
  input.command == "gateway"
  input.gateway.target_host == "db.internal"
  input.gateway.target_port == "5432"
}
`)})
	if err != nil {
		t.Fatal(err)
	}
	req := GatewayPolicyRequest{
		User:       "alice",
		Action:     "direct-tcpip",
		TargetHost: "db.internal",
		TargetIP:   "10.0.0.7",
		TargetPort: 5432,
	}
	if err := hostnameOnly.AuthorizeGateway(req); err != nil {
		t.Fatalf("hostname-only allow policy denied a resolved target: %v", err)
	}

	ipAware, err := NewEngine(EngineConfig{PolicySource: []byte(`
package adssh.authz
import future.keywords.in
default allow = false
default deny_reason = "gateway target is not allowed"
blocked_ips := {"169.254.169.254", "10.0.0.66"}
allow {
  input.command == "gateway"
  input.gateway.target_host == "db.internal"
  not input.gateway.target_ip in blocked_ips
}
deny_reason = "resolved address is blocked" {
  input.gateway.target_ip in blocked_ips
}
`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := ipAware.AuthorizeGateway(req); err != nil {
		t.Fatalf("allowed name and address denied: %v", err)
	}
	rebound := req
	rebound.TargetIP = "10.0.0.66"
	err = ipAware.AuthorizeGateway(rebound)
	if err == nil || !strings.Contains(err.Error(), "resolved address is blocked") {
		t.Fatalf("a blocked target_ip was allowed because the name is allowed: %v", err)
	}

	bad := req
	bad.TargetIP = "not-an-address"
	if err := hostnameOnly.AuthorizeGateway(bad); err == nil {
		t.Fatal("a TargetIP that is not an address was accepted")
	}
}

func TestGatewayTargetIPExamplePolicy(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "policy", "examples", "gateway_target_ip.rego"))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := NewEngine(EngineConfig{PolicySource: src})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		host string
		ip   string
		port uint32
		ok   bool
	}{
		{"name allowed, unresolved", "db.internal", "", 5432, true},
		{"name allowed, address fine", "db.internal", "10.20.0.7", 5432, true},
		{"name allowed, metadata address", "db.internal", "169.254.169.254", 5432, false},
		{"name allowed, blocked subnet", "bastion.internal", "10.99.3.4", 22, false},
		{"name allowed, wrong port", "db.internal", "10.20.0.7", 22, false},
		{"unknown name, allowed subnet", "other.internal", "10.20.0.9", 5432, true},
		{"unknown name, other address", "other.internal", "10.30.0.9", 5432, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := eng.AuthorizeGateway(GatewayPolicyRequest{
				User:       "alice",
				Action:     "direct-tcpip",
				TargetHost: tc.host,
				TargetIP:   tc.ip,
				TargetPort: tc.port,
			})
			if tc.ok && err != nil {
				t.Fatalf("denied: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("allowed")
			}
		})
	}
}

func stubGatewayResolver(t *testing.T, names map[string]string) {
	t.Helper()
	prev := gatewayLookupIP
	gatewayLookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
		if ip, ok := names[host]; ok {
			return []net.IP{net.ParseIP(ip)}, nil
		}
		return nil, fmt.Errorf("no such host")
	}
	t.Cleanup(func() { gatewayLookupIP = prev })
}

func TestGatewayStartPolicyBlocksResolvedTargetIP(t *testing.T) {
	stubGatewayResolver(t, map[string]string{"db.example": "169.254.169.254"})
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(`
package adssh.authz
default allow = false
default deny_reason = "gateway target is not allowed"
allow {
  input.command == "gateway"
  input.gateway.target_host == "db.example"
  input.gateway.target_ip != "169.254.169.254"
}
deny_reason = "resolved address is blocked" {
  input.gateway.target_ip == "169.254.169.254"
}
`)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = runGatewayVBin(t, eng, []string{"gateway", "start", "--listen", "127.0.0.1:0", "--target", "db.example:5432"})
	if err == nil || !strings.Contains(err.Error(), "resolved address is blocked") {
		t.Fatalf("a local gateway to a blocked resolved address started: %v", err)
	}
}

func TestGatewayStartDialsResolvedAddress(t *testing.T) {
	target, closeTarget := startGatewayEchoServer(t)
	defer closeTarget()
	_, port, _ := net.SplitHostPort(target)
	stubGatewayResolver(t, map[string]string{"echo.example": "127.0.0.1"})
	t.Setenv("ADSSH_GATEWAY_LOG", filepath.Join(t.TempDir(), "gw.jsonl"))
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(`
package adssh.authz
default allow = false
allow {
  input.command == "gateway"
  input.gateway.target_host == "echo.example"
  input.gateway.target_ip == "127.0.0.1"
}
allow {
  input.command == "gateway"
  input.args[0] == "stop"
}
`)})
	if err != nil {
		t.Fatal(err)
	}
	output, err := runGatewayVBin(t, eng, []string{"gateway", "start", "--listen", "127.0.0.1:0", "--target", "echo.example:" + port})
	if err != nil {
		t.Fatal(err)
	}
	id, listen := parseGatewayStartOutput(t, output)
	t.Cleanup(func() { _, _ = runGatewayVBin(t, eng, []string{"gateway", "stop", id}) })
	conn, err := net.DialTimeout("tcp", listen, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintln(conn, "ping")
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || line != "echo: ping\n" {
		t.Fatalf("gateway did not dial the resolved address: %q %v", line, err)
	}
}

func TestGatewayStartRefusesUnresolvableTarget(t *testing.T) {
	stubGatewayResolver(t, map[string]string{})
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(`
package adssh.authz
default allow = true
`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runGatewayVBin(t, eng, []string{"gateway", "start", "--listen", "127.0.0.1:0", "--target", "nowhere.example:22"}); err == nil {
		t.Fatal("a gateway to an unresolvable name started")
	}
}
