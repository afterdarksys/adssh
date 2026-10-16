package grid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"

	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/afterdarksys/adssh/security"
)

const allowAllPolicy = "package adssh.authz\ndefault allow = true\n"

type vbinTestError struct{ message string }

func (e *vbinTestError) Error() string { return e.message }

func withGrid(t *testing.T) string {
	t.Helper()
	procGrid.resetGridState()
	dir := scratchTestBase(t)
	procGrid.setScratchRoot(filepath.Join(dir, "worktrees"))
	t.Cleanup(procGrid.resetGridState)
	return dir
}

func testID(t *testing.T, suffix string) string {
	t.Helper()
	id := strings.ReplaceAll(t.Name(), "/", "_") + "_" + suffix
	if !validGridID(id) {
		t.Fatalf("test id is invalid (%d chars)", len(id))
	}
	return id
}

func policyEngine(t *testing.T, source string) *security.Engine {
	t.Helper()
	eng, err := security.NewEngine(security.EngineConfig{PolicySource: []byte(source)})
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func elevatedSession(t *testing.T, suffix, user string) *sys.Session {
	t.Helper()
	session := &sys.Session{ID: testID(t, suffix), User: user}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	session.SetOIDC(security.OIDCProviderAdmin, []string{security.RoleGridOps, security.RoleOSRoot, security.RoleAdsshAdmin})
	session.ActivateElevation(security.RoleGridOps, "grid", time.Now().Add(time.Hour))
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	return session
}

func gridOpsSession(t *testing.T) *sys.Session {
	t.Helper()
	return elevatedSession(t, "ops", "alice")
}

func runVBin(t *testing.T, eng *security.Engine, sessionID string, args []string) (string, error) {
	t.Helper()
	if eng == nil {
		var err error
		eng, err = security.NewEngine(security.EngineConfig{})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(args) == 0 {
		t.Fatal("missing vbin args")
	}
	vb, ok := eng.Lookup(args[0])
	if !ok {
		t.Fatalf("vbin %s is not registered", args[0])
	}
	var out, errOut bytes.Buffer
	runner, err := interp.New(
		interp.StdIO(nil, &out, &errOut),
		interp.ExecHandler(func(ctx context.Context, _ []string) error {
			return eng.DispatchVBin(security.WithSessionID(ctx, sessionID), vb, args)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader("grid-test"), "")
	if err != nil {
		t.Fatal(err)
	}
	runErr := runner.Run(context.Background(), file)
	if runErr == nil && errOut.Len() > 0 {
		runErr = &vbinTestError{message: strings.TrimSpace(errOut.String())}
	}
	return out.String(), runErr
}

func equalErr(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s", want)
	}
	got := err.Error()
	if got != want {
		if strings.Contains(got, "eyJ") {
			t.Fatal("error mismatched and contained a jwt")
		}
		t.Fatalf("got %q want %q", got, want)
	}
}

func writeTokenFile(t *testing.T, path, contents string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func readToken(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

func assertFingerprintHidden(t *testing.T, output, tokenPath string) {
	t.Helper()
	token := readToken(t, tokenPath)
	fingerprint := fingerprintToken(token)
	if token == fingerprint {
		t.Fatal("token and fingerprint collided")
	}
	if !strings.Contains(output, fingerprint) || strings.Contains(output, token) {
		t.Fatal("init output missed fingerprint or contained the token")
	}
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o007 != 0 {
		t.Fatal("token file is world-accessible")
	}
}

func initTestGrid(t *testing.T, id string) string {
	t.Helper()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if _, _, err := procGrid.initGrid(id, "", tokenPath); err != nil {
		t.Fatal(err)
	}
	return tokenPath
}

func writeGridCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	serial.Add(serial, big.NewInt(1))
	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, private.Public(), private)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func serveGrid(t *testing.T, id string, eng *security.Engine) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if _, _, err := procGrid.initGrid(id, "", tokenPath); err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := writeGridCert(t, dir)
	listenURL, err := procGrid.listenGrid("127.0.0.1:0", certFile, keyFile, tokenPath, eng)
	if err != nil {
		t.Fatal(err)
	}
	return listenURL, tokenPath, certFile
}

func postFlightRetry(t *testing.T, eng *security.Engine, opts flightClientOpts) (flightResult, error) {
	t.Helper()
	var result flightResult
	var err error
	for i := 0; i < 20; i++ {
		result, err = postFlight(eng, opts)
		if err == nil || !strings.Contains(err.Error(), "connection refused") {
			return result, err
		}
		time.Sleep(20 * time.Millisecond)
	}
	return result, err
}

func postRaw(t *testing.T, rawURL, caFile, bearer string, body []byte) (int, string) {
	t.Helper()
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("ca file has no certificates")
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    pool,
				ServerName: "localhost",
			},
		},
	}
	var lastErr error
	for i := 0; i < 20; i++ {
		req, err := http.NewRequest(http.MethodPost, rawURL+"/v1/flight", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := client.Do(req)
		if err != nil {
			if strings.Contains(err.Error(), "connection refused") {
				lastErr = err
				time.Sleep(20 * time.Millisecond)
				continue
			}
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		return resp.StatusCode, string(data)
	}
	t.Fatal(lastErr)
	return 0, ""
}

func TestGridInitPrintsFingerprintAndHidesToken(t *testing.T) {
	dir := withGrid(t)
	session := gridOpsSession(t)
	eng := policyEngine(t, allowAllPolicy)

	outPath := filepath.Join(dir, "token-out")
	output, err := runVBin(t, eng, session.ID, []string{
		"grid", "init", "--id", testID(t, "out"), "--token-out", outPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertFingerprintHidden(t, output, outPath)

	second := filepath.Join(dir, "token-out-second")
	_, err = runVBin(t, eng, session.ID, []string{
		"grid", "init", "--id", testID(t, "out2"), "--token-out", second,
	})
	equalErr(t, err, "grid: already initialized")
	if _, statErr := os.Stat(second); !os.IsNotExist(statErr) {
		t.Fatal("second init wrote a token file")
	}

	procGrid.resetGridState()
	procGrid.setScratchRoot(filepath.Join(dir, "worktrees"))
	tokenPath := filepath.Join(dir, "token-file")
	writeTokenFile(t, tokenPath, strings.Repeat("ab", 32)+"\n", 0o600)
	output, err = runVBin(t, eng, session.ID, []string{
		"grid", "init", "--id", testID(t, "file"), "--token-file", tokenPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertFingerprintHidden(t, output, tokenPath)
}

func TestGridInitRejectsWorldAccessibleAndSymlinkToken(t *testing.T) {
	dir := withGrid(t)

	_, _, err := procGrid.initGrid("", "", "")
	equalErr(t, err, "grid: --token-file or --token-out is required")

	_, _, err = procGrid.initGrid(testID(t, "both"), filepath.Join(dir, "a"), filepath.Join(dir, "b"))
	equalErr(t, err, "grid: --token-file and --token-out cannot be combined")

	invalidOut := filepath.Join(dir, "invalid-out")
	_, _, err = procGrid.initGrid("../x", "", invalidOut)
	equalErr(t, err, "grid: invalid id")
	if _, statErr := os.Stat(invalidOut); !os.IsNotExist(statErr) {
		t.Fatal("invalid id wrote a token file")
	}

	world := filepath.Join(dir, "world")
	writeTokenFile(t, world, strings.Repeat("ab", 32)+"\n", 0o644)
	_, _, err = procGrid.initGrid(testID(t, "world"), world, "")
	equalErr(t, err, "grid: token file is readable or writable by group or others")

	target := filepath.Join(dir, "target")
	writeTokenFile(t, target, strings.Repeat("cd", 32)+"\n", 0o644)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, _, err = procGrid.initGrid(testID(t, "sym"), link, "")
	equalErr(t, err, "grid: token file is a symlink")

	group := filepath.Join(dir, "group")
	writeTokenFile(t, group, strings.Repeat("ef", 32)+"\n", 0o640)
	_, _, err = procGrid.initGrid(testID(t, "group"), group, "")
	equalErr(t, err, "grid: token file is readable or writable by group or others")

	private := filepath.Join(dir, "private")
	writeTokenFile(t, private, strings.Repeat("ef", 32)+"\n", 0o600)
	_, fingerprint, err := procGrid.initGrid(testID(t, "private"), private, "")
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != fingerprintToken(readToken(t, private)) {
		t.Fatal("private token fingerprint mismatch")
	}
}

func TestGridRequiresGridOps(t *testing.T) {
	withGrid(t)
	err := gridBinary{}.Run(context.Background(), []string{"grid", "status"})
	equalErr(t, err, "grid: requires an active gridops elevation")

	session := gridOpsSession(t)
	ctx := security.WithSessionID(context.Background(), session.ID)
	err = gridBinary{}.Run(ctx, []string{"grid", "status"})
	equalErr(t, err, "grid: not initialized")

	err = gridBinary{}.Run(ctx, []string{"grid", "status", "--extra"})
	equalErr(t, err, `grid: unknown option "--extra"`)
}

func TestGridServeLoopbackAndRejectsHostname(t *testing.T) {
	dir := withGrid(t)
	session := gridOpsSession(t)
	eng := policyEngine(t, allowAllPolicy)
	tokenPath := initTestGrid(t, testID(t, "grid"))
	certFile, keyFile := writeGridCert(t, dir)
	ctx := security.WithSessionID(context.Background(), session.ID)

	mismatch := filepath.Join(dir, "mismatch")
	writeTokenFile(t, mismatch, strings.Repeat("zz", 32)+"\n", 0o600)
	err := gridBinary{}.Run(ctx, []string{
		"grid", "serve", "--listen", "127.0.0.1:0",
		"--cert", certFile, "--key", keyFile, "--token-file", mismatch,
	})
	equalErr(t, err, "grid: token mismatch")
	_, _, listen, _, _, err := procGrid.gridStatus()
	if err != nil {
		t.Fatal(err)
	}
	if listen != "" {
		t.Fatalf("listen = %q", listen)
	}

	err = gridBinary{}.Run(ctx, []string{
		"grid", "serve", "--listen", "localhost:0",
		"--cert", certFile, "--key", keyFile, "--token-file", tokenPath,
	})
	equalErr(t, err, "grid: listen address must be a loopback IP")

	output, err := runVBin(t, eng, session.ID, []string{
		"grid", "serve", "--listen", "127.0.0.1:0",
		"--cert", certFile, "--key", keyFile, "--token-file", tokenPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(output, "grid: listening https://") {
		t.Fatalf("listen output = %q", output)
	}
	listenURL := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(output), "grid: listening "))
	status, err := runVBin(t, eng, session.ID, []string{"grid", "status"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, listenURL) {
		t.Fatalf("status = %q", status)
	}
}

func TestFlightPlaceRehearseCancelLocal(t *testing.T) {
	withGrid(t)
	session := gridOpsSession(t)
	eng := policyEngine(t, allowAllPolicy)
	initTestGrid(t, testID(t, "grid"))
	ctx := security.WithSessionID(context.Background(), session.ID)

	err := flightBinary{}.Run(ctx, []string{
		"flight", "place", "--id", testID(t, "t0"), "--agent", testID(t, "a0"),
		"--worktree", testID(t, "w0"), "--for", "0s",
	})
	equalErr(t, err, "flight: ttl is invalid")
	err = flightBinary{}.Run(ctx, []string{
		"flight", "place", "--id", testID(t, "t25"), "--agent", testID(t, "a25"),
		"--worktree", testID(t, "w25"), "--for", "25h",
	})
	equalErr(t, err, "flight: ttl is invalid")

	caFile, _ := writeGridCert(t, t.TempDir())
	err = flightBinary{}.Run(ctx, []string{
		"flight", "place", "--id", testID(t, "orphan"), "--agent", testID(t, "oa"),
		"--worktree", testID(t, "ow"), "--for", "10m", "--ca", caFile,
	})
	equalErr(t, err, "flight: --host is required")

	tokenPath := filepath.Join(t.TempDir(), "remote-token")
	writeTokenFile(t, tokenPath, strings.Repeat("ab", 32)+"\n", 0o600)
	err = flightBinary{}.Run(ctx, []string{
		"flight", "place", "--id", testID(t, "ms"), "--agent", testID(t, "ma"),
		"--worktree", testID(t, "mw"), "--for", "1500ms",
		"--host", "https://127.0.0.1:1", "--ca", caFile, "--token-file", tokenPath,
	})
	equalErr(t, err, "flight: ttl is invalid")

	blank := elevatedSession(t, "blank", "")
	err = flightBinary{}.Run(security.WithSessionID(context.Background(), blank.ID), []string{
		"flight", "place", "--id", testID(t, "bf"), "--agent", testID(t, "ba"),
		"--worktree", testID(t, "bw"), "--for", "10m",
	})
	equalErr(t, err, "flight: user is required")

	flightID := testID(t, "f")
	agentID := testID(t, "ag")
	worktreeID := testID(t, "wt")
	output, err := runVBin(t, eng, session.ID, []string{
		"flight", "place", "--id", flightID, "--agent", agentID,
		"--worktree", worktreeID, "--for", "10m",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("flight: id=%s session=agent-%s status=placed", flightID, agentID)
	if !strings.Contains(output, want) {
		t.Fatalf("place output = %q", output)
	}
	agentSession := sys.GetSession("agent-" + agentID)
	if agentSession == nil || agentSession.User != "alice" {
		t.Fatal("placed agent session user is not alice")
	}

	output, err = runVBin(t, eng, session.ID, []string{
		"flight", "rehearse", "--id", flightID, "--", "repo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "status=rehearsed") {
		t.Fatalf("rehearse output = %q", output)
	}

	output, err = runVBin(t, eng, session.ID, []string{"flight", "cancel", "--id", flightID})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "status="+flightStatusCanceled) {
		t.Fatalf("cancel output = %q", output)
	}
	output, err = runVBin(t, eng, session.ID, []string{"agent", "status"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(output) != "agent: none" {
		t.Fatalf("agent status = %q", output)
	}

	for _, item := range []struct{ suffix, ttl string }{{"day", "24h"}, {"sec", "1s"}} {
		output, err = runVBin(t, eng, session.ID, []string{
			"flight", "place", "--id", testID(t, item.suffix),
			"--agent", testID(t, "a"+item.suffix),
			"--worktree", testID(t, "w"+item.suffix),
			"--for", item.ttl,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output, "status=placed") {
			t.Fatalf("place %s output = %q", item.ttl, output)
		}
	}
}

func TestFlightCapReusesCancelledAgentNotFlightID(t *testing.T) {
	withGrid(t)
	eng := policyEngine(t, allowAllPolicy)
	initTestGrid(t, testID(t, "grid"))
	for i := 0; i < gridMaxFlights; i++ {
		_, err := procGrid.placeFlight(placeOpts{
			FlightID:   testID(t, fmt.Sprintf("f%d", i)),
			AgentID:    testID(t, fmt.Sprintf("a%d", i)),
			WorktreeID: testID(t, fmt.Sprintf("w%d", i)),
			TTL:        time.Minute,
			User:       "alice",
			Gate:       eng,
		})
		if err != nil {
			t.Fatalf("place %d: %v", i, err)
		}
	}
	_, err := procGrid.placeFlight(placeOpts{
		FlightID:   testID(t, "f64"),
		AgentID:    testID(t, "a64"),
		WorktreeID: testID(t, "w64"),
		TTL:        time.Minute,
		User:       "alice",
		Gate:       eng,
	})
	equalErr(t, err, "flight: too many flights")

	if _, err := procGrid.cancelFlight(testID(t, "f0"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := procGrid.placeFlight(placeOpts{
		FlightID:   testID(t, "fnew"),
		AgentID:    testID(t, "a0"),
		WorktreeID: testID(t, "w0"),
		TTL:        time.Minute,
		User:       "alice",
		Gate:       eng,
	}); err != nil {
		t.Fatal(err)
	}
	_, err = procGrid.placeFlight(placeOpts{
		FlightID:   testID(t, "f0"),
		AgentID:    testID(t, "anew"),
		WorktreeID: testID(t, "wnew"),
		TTL:        time.Minute,
		User:       "alice",
		Gate:       eng,
	})
	equalErr(t, err, "flight: duplicate id")
	_, err = procGrid.placeFlight(placeOpts{
		FlightID:   testID(t, "extra"),
		AgentID:    testID(t, "ax"),
		WorktreeID: testID(t, "wx"),
		TTL:        time.Minute,
		User:       "alice",
		Gate:       eng,
	})
	equalErr(t, err, "flight: too many flights")
}

func TestDrainedPlaceRejectsAndCancelStatusRehearseWork(t *testing.T) {
	withGrid(t)
	eng := policyEngine(t, allowAllPolicy)
	initTestGrid(t, testID(t, "grid"))
	first := testID(t, "f1")
	second := testID(t, "f2")
	for _, id := range []string{first, second} {
		_, err := procGrid.placeFlight(placeOpts{
			FlightID:   id,
			AgentID:    testID(t, "a"+id[len(id)-1:]),
			WorktreeID: testID(t, "w"+id[len(id)-1:]),
			TTL:        time.Minute,
			User:       "alice",
			Gate:       eng,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := procGrid.drainGrid(); err != nil {
		t.Fatal(err)
	}
	_, err := procGrid.placeFlight(placeOpts{
		FlightID:   testID(t, "f3"),
		AgentID:    testID(t, "a3"),
		WorktreeID: testID(t, "w3"),
		TTL:        time.Minute,
		User:       "alice",
		Gate:       eng,
	})
	equalErr(t, err, "drained")
	if _, err := procGrid.cancelFlight(first, false); err != nil {
		t.Fatal(err)
	}
	status, err := procGrid.flightStatus(second, false)
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "placed" {
		t.Fatalf("status = %s", status.Status)
	}
	result, err := procGrid.rehearseFlight(eng, second, []string{"repo"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "rehearsed" {
		t.Fatalf("rehearse status = %s", result.Status)
	}
}

func TestCancelledRehearsalAllowlistBeforeExpiry(t *testing.T) {
	withGrid(t)
	eng := policyEngine(t, allowAllPolicy)
	initTestGrid(t, testID(t, "grid"))
	flightID := testID(t, "f")
	if _, err := procGrid.placeFlight(placeOpts{
		FlightID:   flightID,
		AgentID:    testID(t, "a"),
		WorktreeID: testID(t, "w"),
		TTL:        time.Minute,
		User:       "alice",
		Gate:       eng,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := procGrid.cancelFlight(flightID, false); err != nil {
		t.Fatal(err)
	}
	result, err := procGrid.rehearseFlight(eng, flightID, []string{"bash"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "denied" || result.Reason != `agent cannot run "bash"` {
		t.Fatalf("status=%s reason=%s", result.Status, result.Reason)
	}
	status, err := procGrid.flightStatus(flightID, false)
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != flightStatusCanceled {
		t.Fatalf("status = %s", status.Status)
	}
	_, err = procGrid.rehearseFlight(eng, flightID, []string{"repo"}, false)
	equalErr(t, err, "flight: agent lease expired")
}

func TestRemoteFlightIgnoresCallerUser(t *testing.T) {
	withGrid(t)
	server := policyEngine(t, "package adssh.authz\ndefault allow = false\nallow { input.user == \"alice\" }\n")
	client := policyEngine(t, allowAllPolicy)
	flightID := testID(t, "f")
	agentID := testID(t, "a")
	worktreeID := testID(t, "w")
	listenURL, tokenPath, certFile := serveGrid(t, testID(t, "grid"), server)
	result, err := postFlightRetry(t, client, flightClientOpts{
		Host:      listenURL,
		CAFile:    certFile,
		TokenFile: tokenPath,
		Action:    "place",
		Wire: flightWire{
			Action:     "place",
			FlightID:   flightID,
			AgentID:    agentID,
			WorktreeID: worktreeID,
			TTLSeconds: 60,
			User:       "alice",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "placed" {
		t.Fatalf("status = %s", result.Status)
	}
	agentSession := sys.GetSession("agent-" + agentID)
	if agentSession == nil || agentSession.User != gridPeerUser {
		t.Fatal("remote place did not bind grid-peer")
	}
	_, err = postFlightRetry(t, client, flightClientOpts{
		Host:      listenURL,
		CAFile:    certFile,
		TokenFile: tokenPath,
		Action:    "rehearse",
		Wire: flightWire{
			Action:   "rehearse",
			FlightID: flightID,
			Command:  []string{"repo"},
			User:     "alice",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "flight: denied:") {
		t.Fatalf("rehearse error = %v", err)
	}
}

func TestRemoteRehearsalGridPeerCloudRepoDoesNotExec(t *testing.T) {
	withGrid(t)
	server := policyEngine(t, `package adssh.authz
default allow = false
allow { input.user == "grid-peer"; input.agent.kind == "cloud"; input.command == "repo" }
`)
	client := policyEngine(t, allowAllPolicy)
	flightID := testID(t, "f")
	agentID := testID(t, "a")
	worktreeID := testID(t, "w")
	listenURL, tokenPath, certFile := serveGrid(t, testID(t, "grid"), server)
	if _, err := postFlightRetry(t, client, flightClientOpts{
		Host:      listenURL,
		CAFile:    certFile,
		TokenFile: tokenPath,
		Action:    "place",
		Wire: flightWire{
			Action:     "place",
			FlightID:   flightID,
			AgentID:    agentID,
			WorktreeID: worktreeID,
			TTLSeconds: 60,
		},
	}); err != nil {
		t.Fatal(err)
	}
	worktreePath, err := procGrid.confinedWorktreePath(worktreeID)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(worktreePath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := postFlightRetry(t, client, flightClientOpts{
		Host:      listenURL,
		CAFile:    certFile,
		TokenFile: tokenPath,
		Action:    "rehearse",
		Wire: flightWire{
			Action:   "rehearse",
			FlightID: flightID,
			Command:  []string{"repo"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "rehearsed" {
		t.Fatalf("status = %s", result.Status)
	}
	after, err := os.ReadDir(worktreePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Fatalf("worktree listing changed from %d to %d entries", len(before), len(after))
	}
	if _, err := os.Stat(filepath.Join(worktreePath, "sentinel")); !os.IsNotExist(err) {
		t.Fatal("rehearsal created a sentinel")
	}
	status, err := procGrid.flightStatus(flightID, false)
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "rehearsed" {
		t.Fatalf("flight status = %s", status.Status)
	}
}

func TestFlightHostRequiresCABeforeDial(t *testing.T) {
	_, err := postFlight(policyEngine(t, allowAllPolicy), flightClientOpts{Host: "https://127.0.0.1:1"})
	equalErr(t, err, "flight: --host requires --ca")
}

func TestFlightRejectsCredentialsAndPlainHTTP(t *testing.T) {
	eng := policyEngine(t, allowAllPolicy)
	certFile, _ := writeGridCert(t, t.TempDir())
	tokenPath := filepath.Join(t.TempDir(), "token")
	writeTokenFile(t, tokenPath, strings.Repeat("ab", 32)+"\n", 0o600)
	_, err := postFlight(eng, flightClientOpts{
		Host:      "https://alice:secret@127.0.0.1:1",
		CAFile:    certFile,
		TokenFile: tokenPath,
		Action:    "status",
		Wire:      flightWire{Action: "status", FlightID: "missing"},
	})
	equalErr(t, err, "flight: credentials are rejected")
	_, err = postFlight(eng, flightClientOpts{
		Host:      "http://127.0.0.1:1",
		CAFile:    certFile,
		TokenFile: tokenPath,
		Action:    "status",
		Wire:      flightWire{Action: "status", FlightID: "missing"},
	})
	equalErr(t, err, "flight: host must be https")
}

func TestFlightWrongCAFailsTLS(t *testing.T) {
	withGrid(t)
	eng := policyEngine(t, allowAllPolicy)
	dirA := t.TempDir()
	dirB := t.TempDir()
	tokenPath := filepath.Join(dirA, "token")
	if _, _, err := procGrid.initGrid(testID(t, "grid"), "", tokenPath); err != nil {
		t.Fatal(err)
	}
	certA, keyA := writeGridCert(t, dirA)
	certB, _ := writeGridCert(t, dirB)
	listenURL, err := procGrid.listenGrid("127.0.0.1:0", certA, keyA, tokenPath, eng)
	if err != nil {
		t.Fatal(err)
	}
	_, err = postFlightRetry(t, eng, flightClientOpts{
		Host:      listenURL,
		CAFile:    certB,
		TokenFile: tokenPath,
		Action:    "status",
		Wire:      flightWire{Action: "status", FlightID: "missing"},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown authority") || strings.Contains(err.Error(), "--host requires --ca") {
		t.Fatalf("tls error = %v", err)
	}
}

func TestFlightPeerAuthAndBodyLimit(t *testing.T) {
	withGrid(t)
	eng := policyEngine(t, allowAllPolicy)
	listenURL, tokenPath, certFile := serveGrid(t, testID(t, "grid"), eng)
	statusBody := []byte(`{"action":"status","flight_id":"missing"}`)

	status, body := postRaw(t, listenURL, certFile, "", statusBody)
	if status != http.StatusUnauthorized || !strings.Contains(body, "unauthorized") {
		t.Fatalf("empty bearer status %d", status)
	}
	status, body = postRaw(t, listenURL, certFile, "not-the-token", statusBody)
	if status != http.StatusUnauthorized || !strings.Contains(body, "unauthorized") {
		t.Fatalf("wrong bearer status %d", status)
	}

	status, body = postRaw(t, listenURL, certFile, "", bytes.Repeat([]byte("a"), gridMaxBody+1))
	if status != http.StatusRequestEntityTooLarge || !strings.Contains(body, "request too large") {
		t.Fatalf("oversize status %d", status)
	}

	prefix := `{"action":"status","flight_id":"missing","pad":"`
	suffix := `"}`
	filler := gridMaxBody - len(prefix) - len(suffix)
	if filler < 0 {
		t.Fatalf("pad prefix is %d bytes", len(prefix)+len(suffix))
	}
	exact := prefix + strings.Repeat("x", filler) + suffix
	if len(exact) != gridMaxBody {
		t.Fatalf("padded body is %d bytes", len(exact))
	}
	status, body = postRaw(t, listenURL, certFile, readToken(t, tokenPath), []byte(exact))
	if status != http.StatusNotFound || !strings.Contains(body, "flight: not found") {
		t.Fatalf("exact body status %d", status)
	}
	if gridTokenMatches(nil, "") {
		t.Fatal("nil token matched an empty bearer")
	}
	if gridTokenMatches(bytes.Repeat([]byte{1}, sha256.Size), strings.Repeat("a", gridMaxTokenFile+1)) {
		t.Fatal("oversized bearer matched")
	}
}

func TestPlaceRequiresPolicy(t *testing.T) {
	withGrid(t)
	unloaded, err := security.NewEngine(security.EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = procGrid.placeFlight(placeOpts{
		FlightID:   testID(t, "local"),
		AgentID:    testID(t, "la"),
		WorktreeID: testID(t, "lw"),
		TTL:        10 * time.Second,
		User:       "alice",
		Gate:       unloaded,
	})
	equalErr(t, err, "policy_required")

	client := policyEngine(t, allowAllPolicy)
	agentID := testID(t, "ra")
	listenURL, tokenPath, certFile := serveGrid(t, testID(t, "grid"), unloaded)
	_, err = postFlightRetry(t, client, flightClientOpts{
		Host:      listenURL,
		CAFile:    certFile,
		TokenFile: tokenPath,
		Action:    "place",
		Wire: flightWire{
			Action:     "place",
			FlightID:   testID(t, "remote"),
			AgentID:    agentID,
			WorktreeID: testID(t, "rw"),
			TTLSeconds: 60,
			User:       "alice",
		},
	})
	equalErr(t, err, "flight: policy_required")
	if sys.GetSession("agent-"+agentID) != nil {
		t.Fatal("policy miss created an agent session")
	}
}

func TestCheckoutRejectsRemoteShortRevAndHooksDoNotRun(t *testing.T) {
	withGrid(t)
	source := t.TempDir()
	cases := []struct {
		source string
		rev    string
		want   string
	}{
		{"https://user:pass@example.com/repo.git", strings.Repeat("ab", 20), "worktree: credentials are rejected"},
		{"https://example.com/repo.git", strings.Repeat("ab", 20), "worktree: remote URLs are rejected"},
		{"git@github.com:org/repo.git", strings.Repeat("ab", 20), "worktree: remote URLs are rejected"},
		{"/tmp/foo:bar", strings.Repeat("ab", 20), "worktree: remote URLs are rejected"},
		{"file://user:pass@localhost/tmp/x", strings.Repeat("ab", 20), "worktree: credentials are rejected"},
		{"rel/repo", strings.Repeat("ab", 20), "worktree: source must be an absolute path"},
		{source, "abc", "worktree: rev must be a 40-character commit hash"},
	}
	for _, item := range cases {
		err := procGrid.checkoutWorktree("c1", item.source, item.rev)
		equalErr(t, err, item.want)
	}

	repo, err := git.PlainInit(source, false)
	if err != nil {
		t.Fatal(err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "pinned.txt"), []byte("pinned-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Add("pinned.txt"); err != nil {
		t.Fatal(err)
	}
	hash, err := worktree.Commit("pin", &git.CommitOptions{Author: &object.Signature{
		Name:  "test",
		Email: "test@example.com",
		When:  time.Now(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "hook-ran")
	hookDir := filepath.Join(source, ".git", "hooks")
	if err := os.MkdirAll(hookDir, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ntouch " + strconv.Quote(marker) + "\n"
	if err := os.WriteFile(filepath.Join(hookDir, "post-checkout"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := procGrid.checkoutWorktree("hook1", source, hash.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("post-checkout hook ran")
	}
	dest, err := procGrid.confinedWorktreePath("hook1")
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := os.ReadFile(filepath.Join(dest, "pinned.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(pinned) != "pinned-bytes" {
		t.Fatal("pinned bytes missing")
	}
}

func TestRepoCatRejectsEscapeAndSymlink(t *testing.T) {
	withGrid(t)
	initTestGrid(t, testID(t, "grid"))
	id := testID(t, "w")
	path, err := procGrid.createWorktree(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "ok.txt"), []byte("ok-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, err := procGrid.repoCat(id, "ok.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "ok-bytes" {
		t.Fatal("cat bytes mismatch")
	}
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(path, "leak")); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"../secret", secret, "foo/../../secret", "leak"} {
		_, err := procGrid.repoCat(id, rel)
		equalErr(t, err, "repo: path escapes worktree")
	}
}

func TestWorktreeAgentCannotCreateAndHumanCanCat(t *testing.T) {
	withGrid(t)
	initTestGrid(t, testID(t, "grid"))
	rev := strings.Repeat("ab", 20)
	source := t.TempDir()

	expired := &sys.Session{ID: testID(t, "expired"), User: "agent"}
	if err := sys.RegisterSession(expired); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(expired.ID) })
	expired.BindManagedAgent(&sys.ManagedAgent{
		ID:        "expired-agent",
		Worktree:  "bound",
		Allow:     []string{"bash"},
		ExpiresAt: time.Now().Add(-time.Hour),
	})
	expiredCtx := security.WithSessionID(context.Background(), expired.ID)
	err := worktreeBinary{}.Run(expiredCtx, []string{"worktree", "create", "--id", "wcreate"})
	equalErr(t, err, "worktree: agents cannot create a worktree")
	err = worktreeBinary{}.Run(expiredCtx, []string{"worktree", "destroy", "--id", "wdestroy"})
	equalErr(t, err, "worktree: agents cannot destroy a worktree")
	err = worktreeBinary{}.Run(expiredCtx, []string{
		"worktree", "checkout", "--id", "other", "--from", source, "--rev", rev,
	})
	equalErr(t, err, "worktree: agent lease expired")
	err = repoBinary{}.Run(expiredCtx, []string{"repo", "cat", "--id", "other", "--path", "ok.txt"})
	equalErr(t, err, "repo: agent lease expired")

	live := &sys.Session{ID: testID(t, "live"), User: "agent"}
	if err := sys.RegisterSession(live); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(live.ID) })
	live.BindManagedAgent(&sys.ManagedAgent{
		ID:        "live-agent",
		Worktree:  "bound",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	liveCtx := security.WithSessionID(context.Background(), live.ID)
	err = worktreeBinary{}.Run(liveCtx, []string{
		"worktree", "checkout", "--id", "other", "--from", source, "--rev", rev,
	})
	equalErr(t, err, "worktree: agent is bound to a different worktree")
	err = repoBinary{}.Run(liveCtx, []string{"repo", "cat", "--id", "other", "--path", "ok.txt"})
	equalErr(t, err, "repo: agent is bound to a different worktree")

	human := elevatedSession(t, "human", "alice")
	eng := policyEngine(t, allowAllPolicy)
	worktreeID := testID(t, "hw")
	if _, err := runVBin(t, eng, human.ID, []string{"worktree", "create", "--id", worktreeID}); err != nil {
		t.Fatal(err)
	}
	worktreePath, err := procGrid.confinedWorktreePath(worktreeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(worktreePath, "ok.txt"), []byte("ok-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	output, err := runVBin(t, eng, human.ID, []string{"repo", "cat", "--id", worktreeID, "--path", "ok.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if output != "ok-bytes" {
		t.Fatalf("cat length %d", len(output))
	}
}

func TestDestroyRefusesSymlink(t *testing.T) {
	withGrid(t)
	initTestGrid(t, testID(t, "grid"))
	path, err := procGrid.createWorktree("sym1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	keep := filepath.Join(target, "keep.txt")
	if err := os.WriteFile(keep, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	equalErr(t, procGrid.destroyWorktree("sym1"), "worktree: destination is a symlink")
	assertFileContents(t, keep, "keep")
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was removed")
	}
}

func TestGridVBinsRegistered(t *testing.T) {
	eng, err := security.NewEngine(security.EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"grid", "flight", "agent", "worktree", "repo"} {
		if _, ok := eng.Lookup(name); !ok {
			t.Fatalf("%s is not registered", name)
		}
	}
	if _, ok := eng.Lookup("git"); ok {
		t.Fatal("git virtual binary is registered")
	}
}
