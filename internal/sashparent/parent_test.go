package sashparent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestEmergencyGrantRunsTheSameProgram(t *testing.T) {
	bin := sashBinary(t)
	g := freshGrant()
	emerSeed := bytes.Repeat([]byte{0x33}, ed25519.SeedSize)
	defer Zero(emerSeed)
	fleetSeed := bytes.Repeat([]byte{0x22}, ed25519.SeedSize)
	defer Zero(fleetSeed)
	doc, pub, err := SignEmergency(g, emerSeed)
	if err != nil {
		t.Fatal(err)
	}
	if subtle.ConstantTimeCompare(pub, publicHalf(emerSeed)) != 1 {
		t.Fatal("emergency public key")
	}
	if !strings.Contains(string(doc), `"purpose":"emergency"`) || strings.Contains(string(doc), "terminal:open") {
		t.Fatal("purpose")
	}
	code, out, errOut, runErr := runScript(t, bin, doc, publicHalf(fleetSeed), pub)
	if runErr != nil || code != 0 || out != "hi\n" || errOut != "" {
		t.Fatalf("emergency code %d out %q err %q run %v", code, out, errOut, runErr)
	}

	fleetDoc, err := signWith("terminal:open", g, ed25519.NewKeyFromSeed(fleetSeed))
	if err != nil {
		t.Fatal(err)
	}
	code, out, errOut, runErr = runScript(t, bin, fleetDoc, publicHalf(fleetSeed), publicHalf(emerSeed))
	if runErr != nil || code != 0 || out != "hi\n" || errOut != "" {
		t.Fatalf("fleet code %d out %q err %q run %v", code, out, errOut, runErr)
	}
}

func TestWrongKeyIsGrantBadSig(t *testing.T) {
	bin := sashBinary(t)
	g := freshGrant()
	fleetSeed := bytes.Repeat([]byte{0x22}, ed25519.SeedSize)
	emerSeed := bytes.Repeat([]byte{0x33}, ed25519.SeedSize)
	defer Zero(fleetSeed)
	defer Zero(emerSeed)
	fleetPriv := ed25519.NewKeyFromSeed(fleetSeed)
	emerPriv := ed25519.NewKeyFromSeed(emerSeed)
	defer Zero(fleetPriv)
	defer Zero(emerPriv)

	fleetSigned, err := signWith("emergency", g, fleetPriv)
	if err != nil {
		t.Fatal(err)
	}
	code, _, errOut, runErr := runScript(t, bin, fleetSigned, publicHalf(fleetSeed), publicHalf(emerSeed))
	if runErr != nil || code != 2 || errOut != "grant_bad_sig\n" {
		t.Fatalf("fleet-on-emergency code %d err %q run %v", code, errOut, runErr)
	}

	emerSigned, err := signWith("terminal:open", g, emerPriv)
	if err != nil {
		t.Fatal(err)
	}
	code, _, errOut, runErr = runScript(t, bin, emerSigned, publicHalf(fleetSeed), publicHalf(emerSeed))
	if runErr != nil || code != 2 || errOut != "grant_bad_sig\n" {
		t.Fatalf("emergency-on-open code %d err %q run %v", code, errOut, runErr)
	}
}

func TestExpiredGrantIsGrantExpired(t *testing.T) {
	bin := sashBinary(t)
	g := freshGrant()
	g.Exp = 1
	seed := bytes.Repeat([]byte{0x33}, ed25519.SeedSize)
	defer Zero(seed)
	doc, pub, err := SignEmergency(g, seed)
	if err != nil {
		t.Fatal(err)
	}
	code, _, errOut, runErr := runScript(t, bin, doc, publicHalf(bytes.Repeat([]byte{0x22}, ed25519.SeedSize)), pub)
	if runErr != nil || code != 2 || errOut != "grant_expired\n" {
		t.Fatalf("code %d err %q run %v", code, errOut, runErr)
	}
}

func TestRunRefusesBeforeExec(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	script := filepath.Join(dir, "marker")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	pub := publicHalf(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	code, err := Run(script, nil, []byte(`{"v":"sash/1"}`), pub, append([]byte(nil), pub...), nil, nil, nil)
	if code != 0 || err != ErrBadSig {
		t.Fatalf("identical code %d err %v", code, err)
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("marker ran")
	}

	code, err = Run(filepath.Join(dir, "missing-sash"), nil, []byte(`{"v":"sash/1"}`), pub, publicHalf(bytes.Repeat([]byte{0x33}, ed25519.SeedSize)), nil, nil, nil)
	if code != 0 || err != ErrSashMiss {
		t.Fatalf("missing code %d err %v", code, err)
	}
	code, err = Run(script, nil, nil, pub, publicHalf(bytes.Repeat([]byte{0x33}, ed25519.SeedSize)), nil, nil, nil)
	if code != 0 || err != ErrMissing {
		t.Fatalf("empty code %d err %v", code, err)
	}
}

func TestSignEmergencyRefusesStarAndFleetPurpose(t *testing.T) {
	seed := bytes.Repeat([]byte{0x33}, ed25519.SeedSize)
	defer Zero(seed)
	g := freshGrant()
	g.AllowPrivate = true
	doc, _, err := SignEmergency(g, seed)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), `"allow_private":false`) || strings.Contains(string(doc), "terminal:open") {
		t.Fatal("document")
	}
	g.Entitlements = []string{"*"}
	doc, _, err = SignEmergency(g, seed)
	if err != ErrStar || doc != nil {
		t.Fatalf("star %v doc %d", err, len(doc))
	}
	g = freshGrant()
	g.Actor = ""
	g.Entitlements = []string{"*"}
	if _, _, err := SignEmergency(g, seed); err != ErrBadShape {
		t.Fatalf("shape before star: %v", err)
	}
	if _, _, err := SignEmergency(freshGrant(), []byte{1, 2, 3}); err != ErrBadSig {
		t.Fatal("short seed")
	}
}

func TestGrantFromEnv(t *testing.T) {
	ok := map[string]string{
		"ADSSH_SASH_ACTOR": "ada",
		"ADSSH_SASH_HOST":  "host-1",
		"ADSSH_SASH_LEASE": "lease-1",
		"ADSSH_SASH_EXP":   "1",
	}
	g, err := GrantFromEnv(func(k string) string { return ok[k] }, time.Now())
	if err != nil || g.Exp != 1 || len(g.Entitlements) != 0 || g.AllowPrivate {
		t.Fatalf("past exp %+v %v", g, err)
	}
	bad := []map[string]string{
		{"ADSSH_SASH_ACTOR": "", "ADSSH_SASH_HOST": "host-1", "ADSSH_SASH_LEASE": "lease-1", "ADSSH_SASH_EXP": "1"},
		{"ADSSH_SASH_ACTOR": "a=b", "ADSSH_SASH_HOST": "host-1", "ADSSH_SASH_LEASE": "lease-1", "ADSSH_SASH_EXP": "1"},
		{"ADSSH_SASH_ACTOR": "a<b", "ADSSH_SASH_HOST": "host-1", "ADSSH_SASH_LEASE": "lease-1", "ADSSH_SASH_EXP": "1"},
		{"ADSSH_SASH_ACTOR": "ada", "ADSSH_SASH_HOST": "host-1", "ADSSH_SASH_LEASE": "a=b", "ADSSH_SASH_EXP": "1"},
		{"ADSSH_SASH_ACTOR": "ada", "ADSSH_SASH_HOST": "host-1", "ADSSH_SASH_LEASE": "lease-1", "ADSSH_SASH_EXP": "08"},
		{"ADSSH_SASH_ACTOR": "ada", "ADSSH_SASH_HOST": "host-1", "ADSSH_SASH_LEASE": "lease-1", "ADSSH_SASH_EXP": "+1"},
		{"ADSSH_SASH_ACTOR": "ada", "ADSSH_SASH_HOST": "host-1", "ADSSH_SASH_LEASE": "lease-1", "ADSSH_SASH_EXP": "0"},
		{"ADSSH_SASH_ACTOR": "ada", "ADSSH_SASH_HOST": "host-1", "ADSSH_SASH_LEASE": "lease-1", "ADSSH_SASH_EXP": ""},
	}
	for _, env := range bad {
		if _, err := GrantFromEnv(func(k string) string { return env[k] }, time.Now()); err != ErrBadShape {
			t.Fatalf("%v: %v", env["ADSSH_SASH_ACTOR"]+env["ADSSH_SASH_EXP"], err)
		}
	}
}

func TestReadKeyFiles(t *testing.T) {
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed")
	pubPath := filepath.Join(dir, "fleet.pub")
	rawSeed := bytes.Repeat([]byte{0x33}, ed25519.SeedSize)
	rawFleet := publicHalf(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	if err := os.WriteFile(seedPath, rawSeed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, rawFleet, 0o644); err != nil {
		t.Fatal(err)
	}
	gotSeed, gotPub, err := ReadKeyFiles(seedPath, pubPath)
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(gotSeed)
	if subtle.ConstantTimeCompare(gotSeed, rawSeed) != 1 || subtle.ConstantTimeCompare(gotPub, rawFleet) != 1 {
		t.Fatal("key bytes")
	}

	if err := os.Chmod(seedPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadKeyFiles(seedPath, pubPath); err != ErrBadSig {
		t.Fatalf("group seed %v", err)
	}
	if err := os.Chmod(seedPath, 0o600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(dir, "seed-link")
	if err := os.Symlink(seedPath, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadKeyFiles(link, pubPath); err != ErrBadSig {
		t.Fatalf("seed symlink %v", err)
	}
	pubLink := filepath.Join(dir, "pub-link")
	if err := os.Symlink(pubPath, pubLink); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadKeyFiles(seedPath, pubLink); err != ErrBadSig {
		t.Fatalf("pub symlink %v", err)
	}
	short := filepath.Join(dir, "short")
	if err := os.WriteFile(short, rawSeed[:16], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadKeyFiles(short, pubPath); err != ErrBadSig {
		t.Fatalf("short %v", err)
	}
	if _, _, err := ReadKeyFiles(filepath.Join(dir, "missing"), pubPath); err != ErrBadSig {
		t.Fatalf("missing %v", err)
	}
}

func TestServeDenyAndOversizeFrame(t *testing.T) {
	sp, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	syscall.CloseOnExec(sp[0])
	syscall.CloseOnExec(sp[1])
	parent := os.NewFile(uintptr(sp[0]), "verb-parent")
	child := os.NewFile(uintptr(sp[1]), "verb-child")
	done := make(chan error, 1)
	go func() { done <- serveDeny(parent) }()
	if err := writeFrame(child, verbReq{Key: "ps"}); err != nil {
		t.Fatal(err)
	}
	var raw bytes.Buffer
	var n [4]byte
	if _, err := io.ReadFull(child, n[:]); err != nil {
		t.Fatal(err)
	}
	size := binary.BigEndian.Uint32(n[:])
	body := make([]byte, size)
	if _, err := io.ReadFull(child, body); err != nil {
		t.Fatal(err)
	}
	raw.Write(body)
	if raw.String() != `{"error":"denied"}` {
		t.Fatalf("deny %s", raw.String())
	}
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := parent.Close(); err != nil && !gone(err) {
		t.Fatal(err)
	}

	var frame bytes.Buffer
	binary.BigEndian.PutUint32(n[:], maxFrame+1)
	frame.Write(n[:])
	frame.WriteString("BODY")
	err = readFrame(&frame, &verbReq{})
	if err == nil || err.Error() != "frame too large" {
		t.Fatalf("oversize %v", err)
	}
	rest, err := io.ReadAll(&frame)
	if err != nil || string(rest) != "BODY" {
		t.Fatalf("unread %q %v", rest, err)
	}
}

func freshGrant() Grant {
	return Grant{
		Actor:        "ada",
		Host:         "33333333-3333-4333-8333-333333333333",
		Exp:          time.Now().Add(time.Hour).Unix(),
		LeaseID:      "lease-1",
		Entitlements: []string{},
		FileRead:     []string{},
		FileWrite:    []string{},
	}
}

func publicHalf(seed []byte) ed25519.PublicKey {
	priv := ed25519.NewKeyFromSeed(seed)
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pub, priv[ed25519.SeedSize:])
	Zero(priv)
	return pub
}

func runScript(t *testing.T, bin string, doc, fleet, emer []byte) (int, string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code, err := Run(bin, []string{"--session", "-c", "echo hi"}, doc, fleet, emer, strings.NewReader(""), &stdout, &stderr)
	return code, stdout.String(), stderr.String(), err
}

var (
	sashOnce sync.Once
	sashBin  string
	sashErr  error
)

func sashBinary(t *testing.T) string {
	t.Helper()
	sashOnce.Do(func() {
		_, file, _, ok := runtime.Caller(0)
		if !ok {
			sashErr = errors.New("caller")
			return
		}
		root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
		dir, err := os.MkdirTemp("", "sashparent-bin-")
		if err != nil {
			sashErr = err
			return
		}
		sashBin = filepath.Join(dir, "sash")
		cmd := exec.Command("go", "build", "-o", sashBin, ".")
		cmd.Dir = filepath.Join(root, "sash", "cmd", "sash")
		out, err := cmd.CombinedOutput()
		if err != nil {
			sashErr = errors.New(strings.TrimSpace(string(out)))
			if sashErr.Error() == "" {
				sashErr = err
			}
		}
	})
	if sashErr != nil {
		t.Fatal(sashErr)
	}
	return sashBin
}
