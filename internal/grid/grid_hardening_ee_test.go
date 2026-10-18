//go:build ee

package grid

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/afterdarksys/adssh/security"
)

// scratchTestBase returns a directory whose ancestors are not world-writable,
// so it can hold a scratch root. On hosts where t.TempDir() lives under /tmp
// it falls back to a private directory under the package directory.
func scratchTestBase(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if refuseWorldWritableAncestor(filepath.Join(dir, "worktrees")) == nil {
		return dir
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir, err = os.MkdirTemp(wd, ".grid-scratch-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}

func plainSession(t *testing.T, suffix, user string) *sys.Session {
	t.Helper()
	session := &sys.Session{ID: testID(t, suffix), User: user}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	return session
}

func commitRepo(t *testing.T, dir, contents string) string {
	t.Helper()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Add("file.txt"); err != nil {
		t.Fatal(err)
	}
	hash, err := worktree.Commit("c", &git.CommitOptions{Author: &object.Signature{
		Name: "test", Email: "test@example.com", When: time.Now(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return hash.String()
}

func assertFileContents(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if string(data) != want {
		t.Fatalf("%s changed", path)
	}
}

func TestWorktreeDestroySymlinkedRootRefusedAndNothingDeleted(t *testing.T) {
	procGrid.resetGridState()
	t.Cleanup(procGrid.resetGridState)
	base := scratchTestBase(t)
	victim := filepath.Join(base, "victim")
	if err := os.MkdirAll(filepath.Join(victim, "projects"), 0o700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(victim, "projects", "keep.txt")
	if err := os.WriteFile(keep, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "root")
	if err := os.Symlink(victim, root); err != nil {
		t.Fatal(err)
	}
	procGrid.setScratchRoot(root)
	initTestGrid(t, testID(t, "grid"))
	session := gridOpsSession(t)
	eng := policyEngine(t, allowAllPolicy)

	_, err := runVBin(t, eng, session.ID, []string{"worktree", "destroy", "--id", "projects"})
	equalErr(t, err, "worktree: not found")
	_, err = runVBin(t, eng, session.ID, []string{"worktree", "create", "--id", "projects"})
	equalErr(t, err, "worktree: scratch root is a symlink")

	// Even a recorded id is refused when the root is a symlink.
	procGrid.mu.Lock()
	procGrid.member.worktrees["projects"] = ""
	procGrid.mu.Unlock()
	equalErr(t, procGrid.destroyWorktree("projects"), "worktree: scratch root is a symlink")
	assertFileContents(t, keep, "keep")
}

func TestWorktreeDestroyUnrecordedIDRefused(t *testing.T) {
	withGrid(t)
	initTestGrid(t, testID(t, "grid"))
	path, err := procGrid.confinedWorktreePath("other")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(path, "keep.txt")
	if err := os.WriteFile(keep, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	session := gridOpsSession(t)
	_, err = runVBin(t, policyEngine(t, allowAllPolicy), session.ID, []string{"worktree", "destroy", "--id", "other"})
	equalErr(t, err, "worktree: not found")
	assertFileContents(t, keep, "keep")

	created, err := procGrid.createWorktree("made")
	if err != nil {
		t.Fatal(err)
	}
	if err := procGrid.destroyWorktree("made"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(created); !os.IsNotExist(err) {
		t.Fatal("recorded worktree was not removed")
	}
	equalErr(t, procGrid.destroyWorktree("made"), "worktree: not found")
}

func TestWorktreeDestroyWithoutGridOpsOrGridRefused(t *testing.T) {
	withGrid(t)
	equalErr(t, procGrid.destroyWorktree("nogrid"), "grid: not initialized")
	initTestGrid(t, testID(t, "grid"))
	path, err := procGrid.createWorktree("held")
	if err != nil {
		t.Fatal(err)
	}
	plain := plainSession(t, "plain", "mallory")
	ctx := security.WithSessionID(context.Background(), plain.ID)
	rev := strings.Repeat("ab", 20)
	for _, args := range [][]string{
		{"worktree", "destroy", "--id", "held"},
		{"worktree", "create", "--id", "fresh"},
		{"worktree", "checkout", "--id", "held", "--from", t.TempDir(), "--rev", rev},
	} {
		equalErr(t, worktreeBinary{}.Run(ctx, args), "worktree: requires an active gridops elevation")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("worktree removed without gridops")
	}
}

func TestScratchRootUnderTmpRefused(t *testing.T) {
	procGrid.resetGridState()
	t.Cleanup(procGrid.resetGridState)
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join("/tmp", "adssh-worktrees-"+hex.EncodeToString(buf[:]))
	procGrid.setScratchRoot(root)
	_, err := procGrid.confinedWorktreePath("w1")
	equalErr(t, err, "worktree: scratch root is under a world-writable directory")
	if _, statErr := os.Lstat(root); !os.IsNotExist(statErr) {
		t.Fatal("refused root was created")
	}

	base := scratchTestBase(t)
	loose := filepath.Join(base, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	procGrid.setScratchRoot(loose)
	_, err = procGrid.confinedWorktreePath("w1")
	equalErr(t, err, "worktree: scratch root mode must be 0700")

	procGrid.setScratchRoot("relative/root")
	_, err = procGrid.confinedWorktreePath("w1")
	equalErr(t, err, "worktree: scratch root must be absolute")

	fresh := filepath.Join(base, "fresh", "worktrees")
	procGrid.setScratchRoot(fresh)
	if _, err := procGrid.confinedWorktreePath("w1"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("created root mode %o", info.Mode().Perm())
	}

	t.Setenv("XDG_DATA_HOME", "")
	def := defaultScratchRoot()
	if strings.HasPrefix(def, filepath.Clean(os.TempDir())) || strings.HasPrefix(def, "/tmp") {
		t.Fatalf("default scratch root %s is under the temp dir", def)
	}
}

func TestRemoteCancelAndStatusOnlyRemoteFlights(t *testing.T) {
	withGrid(t)
	eng := policyEngine(t, allowAllPolicy)
	listenURL, tokenPath, certFile := serveGrid(t, testID(t, "grid"), eng)
	localID := testID(t, "local")
	if _, err := procGrid.placeFlight(placeOpts{
		FlightID: localID, AgentID: testID(t, "la"), WorktreeID: testID(t, "lw"),
		TTL: time.Minute, User: "alice", Gate: eng,
	}); err != nil {
		t.Fatal(err)
	}
	remoteID := testID(t, "remote")
	opts := func(action, id string) flightClientOpts {
		return flightClientOpts{
			Host: listenURL, CAFile: certFile, TokenFile: tokenPath, Action: action,
			Wire: flightWire{Action: action, FlightID: id, AgentID: testID(t, "ra"),
				WorktreeID: testID(t, "rw"), TTLSeconds: 60},
		}
	}
	if _, err := postFlightRetry(t, eng, opts("place", remoteID)); err != nil {
		t.Fatal(err)
	}

	for _, action := range []string{"cancel", "status"} {
		_, err := postFlightRetry(t, eng, opts(action, localID))
		equalErr(t, err, "flight: flight: not found")
	}
	status, err := procGrid.flightStatus(localID, false)
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "placed" {
		t.Fatalf("local flight status = %s", status.Status)
	}
	if sys.GetSession("agent-"+testID(t, "la")) == nil {
		t.Fatal("remote cancel released a local agent session")
	}

	result, err := postFlightRetry(t, eng, opts("status", remoteID))
	if err != nil || result.Status != "placed" {
		t.Fatalf("remote status = %v %v", result, err)
	}
	result, err = postFlightRetry(t, eng, opts("cancel", remoteID))
	if err != nil || result.Status != flightStatusCanceled {
		t.Fatalf("remote cancel = %v %v", result, err)
	}
}

func TestRemoteCancelStatusRequirePolicy(t *testing.T) {
	withGrid(t)
	unloaded, err := security.NewEngine(security.EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	initTestGrid(t, testID(t, "grid"))
	for _, action := range []string{"cancel", "status"} {
		_, err := procGrid.dispatchFlightAction(unloaded, action, flightWire{FlightID: "missing"}, true)
		equalErr(t, err, "policy_required")
	}
}

func expireAllFlights(t *testing.T) {
	t.Helper()
	procGrid.mu.Lock()
	defer procGrid.mu.Unlock()
	for _, rec := range procGrid.member.flights {
		rec.ExpiresAt = time.Now().Add(-time.Second)
	}
}

func TestExpiredFlightsDoNotBlockPlace(t *testing.T) {
	withGrid(t)
	eng := policyEngine(t, allowAllPolicy)
	initTestGrid(t, testID(t, "grid"))
	for i := 0; i < gridMaxFlights; i++ {
		if _, err := procGrid.placeFlight(placeOpts{
			FlightID: testID(t, "f"+strconv.Itoa(i)), AgentID: testID(t, "a"+strconv.Itoa(i)),
			WorktreeID: testID(t, "w"+strconv.Itoa(i)), TTL: time.Minute, User: "alice", Gate: eng,
		}); err != nil {
			t.Fatalf("place %d: %v", i, err)
		}
	}
	expireAllFlights(t)
	if _, err := procGrid.placeFlight(placeOpts{
		FlightID: testID(t, "fnew"), AgentID: testID(t, "a0"), WorktreeID: testID(t, "w0"),
		TTL: time.Minute, User: "alice", Gate: eng,
	}); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < gridMaxFlights; i++ {
		if sys.GetSession("agent-"+testID(t, "a"+strconv.Itoa(i))) != nil {
			t.Fatalf("expired agent %d is still registered", i)
		}
	}
	status, err := procGrid.flightStatus(testID(t, "f1"), false)
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != flightStatusCanceled || status.Reason != "lease expired" {
		t.Fatalf("expired status=%s reason=%s", status.Status, status.Reason)
	}
	_, _, _, _, live, err := procGrid.gridStatus()
	if err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Fatalf("live flights = %d", live)
	}

	procGrid.mu.Lock()
	procGrid.member.flights[testID(t, "f1")].CancelledAt = time.Now().Add(-2 * gridCancelledRetention)
	procGrid.mu.Unlock()
	procGrid.reapExpiredFlights(time.Now())
	_, err = procGrid.flightStatus(testID(t, "f1"), false)
	equalErr(t, err, "flight: not found")
	if _, err := procGrid.flightStatus(testID(t, "f2"), false); err != nil {
		t.Fatal("recently canceled flight was pruned")
	}
}

func TestGridReaperExpiresFlightsWhileListening(t *testing.T) {
	withGrid(t)
	previous := procGrid.reapInterval
	procGrid.reapInterval = 20 * time.Millisecond
	t.Cleanup(func() { procGrid.reapInterval = previous })
	eng := policyEngine(t, allowAllPolicy)
	serveGrid(t, testID(t, "grid"), eng)
	flightID := testID(t, "f")
	agentID := testID(t, "a")
	if _, err := procGrid.placeFlight(placeOpts{
		FlightID: flightID, AgentID: agentID, WorktreeID: testID(t, "w"),
		TTL: time.Minute, User: "alice", Gate: eng,
	}); err != nil {
		t.Fatal(err)
	}
	expireAllFlights(t)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		status, err := procGrid.flightStatus(flightID, false)
		if err != nil {
			t.Fatal(err)
		}
		if status.Status == flightStatusCanceled {
			if sys.GetSession("agent-"+agentID) != nil {
				t.Fatal("reaped agent session is still registered")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("reaper did not cancel the expired flight")
}

func TestAgentCheckoutUsesBoundSource(t *testing.T) {
	withGrid(t)
	initTestGrid(t, testID(t, "grid"))
	eng := policyEngine(t, allowAllPolicy)
	ops := gridOpsSession(t)
	bound := t.TempDir()
	rev := commitRepo(t, bound, "bound-bytes")
	other := t.TempDir()
	otherRev := commitRepo(t, other, "other-bytes")

	flightID := testID(t, "f")
	agentID := testID(t, "a")
	worktreeID := testID(t, "w")
	if _, err := runVBin(t, eng, ops.ID, []string{
		"flight", "place", "--id", flightID, "--agent", agentID,
		"--worktree", worktreeID, "--for", "10m", "--source", bound,
	}); err != nil {
		t.Fatal(err)
	}
	agentCtx := security.WithSessionID(context.Background(), "agent-"+agentID)
	err := worktreeBinary{}.Run(agentCtx, []string{
		"worktree", "checkout", "--id", worktreeID, "--from", other, "--rev", otherRev,
	})
	equalErr(t, err, "worktree: source is not the flight's bound source")
	err = worktreeBinary{}.Run(agentCtx, []string{
		"worktree", "checkout", "--id", worktreeID, "--from", "file://" + other, "--rev", otherRev,
	})
	equalErr(t, err, "worktree: source is not the flight's bound source")
	dest, err := procGrid.confinedWorktreePath(worktreeID)
	if err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(dest); err != nil || len(entries) != 0 {
		t.Fatal("refused checkout wrote into the worktree")
	}

	if _, err := runVBin(t, eng, "agent-"+agentID, []string{
		"worktree", "checkout", "--id", worktreeID, "--rev", rev,
	}); err != nil {
		t.Fatal(err)
	}
	assertFileContents(t, filepath.Join(dest, "file.txt"), "bound-bytes")

	unbound := testID(t, "ua")
	if _, err := runVBin(t, eng, ops.ID, []string{
		"flight", "place", "--id", testID(t, "uf"), "--agent", unbound,
		"--worktree", testID(t, "uw"), "--for", "10m",
	}); err != nil {
		t.Fatal(err)
	}
	err = worktreeBinary{}.Run(security.WithSessionID(context.Background(), "agent-"+unbound), []string{
		"worktree", "checkout", "--id", testID(t, "uw"), "--from", bound, "--rev", rev,
	})
	equalErr(t, err, "worktree: agent has no bound source")

	caFile, _ := writeGridCert(t, t.TempDir())
	tokenPath := filepath.Join(t.TempDir(), "remote-token")
	writeTokenFile(t, tokenPath, strings.Repeat("ab", 32)+"\n", 0o600)
	_, err = runVBin(t, eng, ops.ID, []string{
		"flight", "place", "--id", testID(t, "rf"), "--agent", testID(t, "rag"),
		"--worktree", testID(t, "rw"), "--for", "10m", "--source", bound,
		"--host", "https://127.0.0.1:1", "--ca", caFile, "--token-file", tokenPath,
	})
	equalErr(t, err, "flight: --source cannot be sent to a remote host")
}

func TestMembershipTokenRejectsGroupReadableAndSymlink(t *testing.T) {
	dir := t.TempDir()
	group := filepath.Join(dir, "group")
	writeTokenFile(t, group, strings.Repeat("ab", 32)+"\n", 0o640)
	_, _, err := loadMembershipToken(group)
	equalErr(t, err, "grid: token file is readable or writable by group or others")

	groupWrite := filepath.Join(dir, "group-write")
	writeTokenFile(t, groupWrite, strings.Repeat("ab", 32)+"\n", 0o620)
	_, _, err = loadMembershipToken(groupWrite)
	equalErr(t, err, "grid: token file is readable or writable by group or others")

	target := filepath.Join(dir, "target")
	writeTokenFile(t, target, strings.Repeat("cd", 32)+"\n", 0o600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, _, err = loadMembershipToken(link)
	equalErr(t, err, "grid: token file is a symlink")

	sub := filepath.Join(dir, "subdir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	_, _, err = loadMembershipToken(sub)
	equalErr(t, err, "grid: token file is not a regular file")

	token, hash, err := loadMembershipToken(target)
	if err != nil || token != strings.Repeat("cd", 32) || len(hash) != 32 {
		t.Fatalf("private token load failed: %v", err)
	}
}
