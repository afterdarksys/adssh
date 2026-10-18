//go:build !ee

package security

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"
)

// The core build lets a user attach to their own session only. Privileged
// supervision and share grants are enterprise, so an adssh-admin attach to
// someone else's session and mirror share are refused and audited.
func TestCoreMirrorAttachOwnSessionOnly(t *testing.T) {
	dir := t.TempDir()
	chainPath := filepath.Join(dir, "audit.chain")
	eng, err := NewEngine(EngineConfig{ChainPath: chainPath, ChainKeyPath: filepath.Join(dir, "audit.key"), SessionID: "core-mirror"})
	if err != nil {
		t.Fatal(err)
	}
	owner := &sys.Session{ID: "core-mirror-owner", User: "alice", Out: sys.NewOutputBroadcaster(&bytes.Buffer{})}
	second := &sys.Session{ID: "core-mirror-second", User: "alice"}
	admin := &sys.Session{ID: "core-mirror-admin", User: "root-op", Principals: []string{RoleAdsshAdmin, RoleOSRoot}}
	for _, s := range []*sys.Session{owner, second, admin} {
		registerTestSession(t, s)
	}

	if err := eng.mirrorAuthorize(second.ID, owner.ID, true); err != nil {
		t.Fatalf("owner attach to own session refused: %v", err)
	}
	err = eng.mirrorAuthorize(admin.ID, owner.ID, false)
	if err == nil || !strings.Contains(err.Error(), "enterprise") {
		t.Fatalf("SECURITY: privileged attach to another user's session in core: %v", err)
	}
	if _, err := runSessionVBin(t, eng, mirrorBinary{}, owner.ID, []string{"mirror", "share", "--with", "bob", "--for", "5m"}); err == nil || !strings.Contains(err.Error(), "enterprise") {
		t.Fatalf("mirror share in core: %v", err)
	}
	chain, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(chain), "MIRROR_DENIED: session=core-mirror-owner user=root-op") {
		t.Fatalf("refused attach not audited:\n%s", chain)
	}
}
