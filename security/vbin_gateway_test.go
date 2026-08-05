package security

import (
	"bufio"
	"bytes"
	"context"
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
