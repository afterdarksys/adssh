//go:build ee

package security

import (
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
)

// Threats: viewing or driving another user's session is a privilege. A user
// may attach to a session only when it is their own, when they hold
// adssh-admin or os-root (directly or by an active elevation), or when the
// session's owner granted them access with `mirror share`. A grant names one
// user, is view-only unless --console was given, ends at a fixed expiry (at
// most 24h), and is revocable with `mirror unshare`. A grant is void when the
// session's user is no longer the user who made it. A managed-agent session
// can neither share nor attach. Every grant, revoke, expiry, attach, and
// refusal is an audit event. The `mirror share` command itself passes the
// normal policy gate with its argv in input.args.
// Grants are dropped when the session unregisters.
// Non-goals: grants live in this process's memory and do not survive a
// restart. They are keyed by session ID, not stored in internal/sys.

const maxMirrorShare = 24 * time.Hour

var mirrorGranteePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

type mirrorGrant struct {
	owner     string
	grantee   string
	console   bool
	expiresAt time.Time
	engine    *Engine
	timer     *time.Timer
}

var (
	mirrorGrantsMu sync.Mutex
	// mirrorGrants maps an owner session ID to its grants by grantee user.
	mirrorGrants = map[string]map[string]*mirrorGrant{}
	mirrorClock  = time.Now
)

// setMirrorClock replaces the clock used for grant expiry. Tests only.
func setMirrorClock(now func() time.Time) (restore func()) {
	mirrorGrantsMu.Lock()
	prev := mirrorClock
	mirrorClock = now
	mirrorGrantsMu.Unlock()
	return func() {
		mirrorGrantsMu.Lock()
		mirrorClock = prev
		mirrorGrantsMu.Unlock()
	}
}

// Grants on a session end with it.
func init() { sys.OnSessionUnregister(clearMirrorGrants) }

// clearMirrorGrants drops every grant on sessionID without auditing.
func clearMirrorGrants(sessionID string) {
	mirrorGrantsMu.Lock()
	defer mirrorGrantsMu.Unlock()
	for _, g := range mirrorGrants[sessionID] {
		g.timer.Stop()
	}
	delete(mirrorGrants, sessionID)
}

// shareMirror grants grantee access to ownerSessionID for d.
func (e *Engine) shareMirror(ownerSessionID, grantee string, d time.Duration, console bool) error {
	if sys.GetSession(ownerSessionID) == nil {
		return fmt.Errorf("mirror share: requires a registered session")
	}
	owner := e.buildPolicyContext("mirror", nil, ownerSessionID)
	if owner.IdentityUnknown || owner.User == "" {
		return fmt.Errorf("mirror share: session identity unknown")
	}
	if owner.Agent != nil {
		return fmt.Errorf("mirror share: agent sessions cannot share")
	}
	if !mirrorGranteePattern.MatchString(grantee) {
		return fmt.Errorf("mirror share: invalid user %q", grantee)
	}
	if grantee == owner.User {
		return fmt.Errorf("mirror share: %s already owns this session", grantee)
	}
	if d <= 0 || d > maxMirrorShare {
		return fmt.Errorf("mirror share: --for must be between 1s and %s", maxMirrorShare)
	}

	mirrorGrantsMu.Lock()
	g := &mirrorGrant{
		owner:     owner.User,
		grantee:   grantee,
		console:   console,
		expiresAt: mirrorClock().Add(d),
		engine:    e,
	}
	grants := mirrorGrants[ownerSessionID]
	if grants == nil {
		grants = map[string]*mirrorGrant{}
		mirrorGrants[ownerSessionID] = grants
	}
	if prev := grants[grantee]; prev != nil {
		prev.timer.Stop()
	}
	grants[grantee] = g
	g.timer = time.AfterFunc(d, func() { expireMirrorGrant(ownerSessionID, g) })
	mirrorGrantsMu.Unlock()

	return e.LogEvent(fmt.Sprintf("MIRROR_SHARE: session=%s owner=%s with=%s mode=%s expires=%s",
		ownerSessionID, g.owner, grantee, mirrorMode(console), g.expiresAt.UTC().Format(time.RFC3339)))
}

// unshareMirror revokes grantee's grant, or every grant when grantee is "".
func (e *Engine) unshareMirror(ownerSessionID, grantee string) (int, error) {
	mirrorGrantsMu.Lock()
	var revoked []*mirrorGrant
	for name, g := range mirrorGrants[ownerSessionID] {
		if grantee != "" && name != grantee {
			continue
		}
		g.timer.Stop()
		delete(mirrorGrants[ownerSessionID], name)
		revoked = append(revoked, g)
	}
	if len(mirrorGrants[ownerSessionID]) == 0 {
		delete(mirrorGrants, ownerSessionID)
	}
	mirrorGrantsMu.Unlock()

	if len(revoked) == 0 {
		if grantee == "" {
			return 0, fmt.Errorf("mirror unshare: this session has no grants")
		}
		return 0, fmt.Errorf("mirror unshare: no grant for %s", grantee)
	}
	sort.Slice(revoked, func(i, j int) bool { return revoked[i].grantee < revoked[j].grantee })
	for _, g := range revoked {
		if err := e.LogEvent(fmt.Sprintf("MIRROR_UNSHARE: session=%s owner=%s with=%s mode=%s",
			ownerSessionID, g.owner, g.grantee, mirrorMode(g.console))); err != nil {
			return len(revoked), err
		}
	}
	return len(revoked), nil
}

// expireMirrorGrant removes g if it is still the live grant and audits it once.
func expireMirrorGrant(ownerSessionID string, g *mirrorGrant) {
	mirrorGrantsMu.Lock()
	grants := mirrorGrants[ownerSessionID]
	if grants == nil || grants[g.grantee] != g {
		mirrorGrantsMu.Unlock()
		return
	}
	delete(grants, g.grantee)
	if len(grants) == 0 {
		delete(mirrorGrants, ownerSessionID)
	}
	mirrorGrantsMu.Unlock()
	g.timer.Stop()
	// The grant is already gone; a failed write is reported, not dropped.
	if err := g.engine.LogEvent(fmt.Sprintf("MIRROR_SHARE_EXPIRED: session=%s owner=%s with=%s mode=%s",
		ownerSessionID, g.owner, g.grantee, mirrorMode(g.console))); err != nil {
		warnUnrecordedRevocation("MIRROR_SHARE_EXPIRED", err)
	}
}

// liveMirrorGrant returns grantee's unexpired grant on ownerSessionID. An
// expired grant is removed and audited.
func liveMirrorGrant(ownerSessionID, grantee string) *mirrorGrant {
	mirrorGrantsMu.Lock()
	g := mirrorGrants[ownerSessionID][grantee]
	expired := g != nil && !mirrorClock().Before(g.expiresAt)
	mirrorGrantsMu.Unlock()
	if expired {
		expireMirrorGrant(ownerSessionID, g)
		return nil
	}
	return g
}

func init() { mirrorPeerAccess = enterpriseMirrorPeerAccess }

// enterpriseMirrorPeerAccess lets adssh-admin and os-root supervise any
// session, and any other user attach with a live share grant from the
// session's owner.
func enterpriseMirrorPeerAccess(pctx, target PolicyContext, targetID string, console bool) (string, error) {
	for _, group := range pctx.Groups {
		if group == RoleAdsshAdmin || group == RoleOSRoot {
			return "privileged", nil
		}
	}
	g := liveMirrorGrant(targetID, pctx.User)
	if g == nil || g.owner != target.User {
		return "", fmt.Errorf("mirror: %s has no grant to %s session %s", pctx.User, mirrorMode(console), targetID)
	}
	if console && !g.console {
		return "", fmt.Errorf("mirror: %s's grant on session %s is view-only", pctx.User, targetID)
	}
	return "grant", nil
}
