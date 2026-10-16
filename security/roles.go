package security

// Threats: a login-audience groups claim, a legacy unsigned import, or
// grant request must not turn os-root, adssh-admin, or gridops into a
// principal. Eligible roles are recorded only for an admin-audience import
// and are not an elevation by themselves. A managed agent may run only the
// fixed command-name allowlist.
// Non-goals: this does not stop a stolen admin-audience JWT before it
// expires, and it does not change the OS uid.

const (
	RoleAdsshAdmin    = "adssh-admin"
	RoleOSRoot        = "os-root"
	RoleGridOps       = "gridops"
	OIDCProviderLogin = "login"
	OIDCProviderAdmin = "admin"
	agentKindCloud    = "cloud"
)

// agentAllow is the only command names a cloud-agent session may pass to
// the shell gate. Subcommands are checked again inside each virtual binary.
var agentAllow = []string{
	"worktree",
	"repo",
	"runbook",
	"par",
	"why",
	"??",
	"evidence",
	"lease",
}

// IsPrivilegedRole reports whether role is one of the three elevated roles
// that cannot be assumed from a login audience or from grant.
func IsPrivilegedRole(role string) bool {
	switch role {
	case RoleAdsshAdmin, RoleOSRoot, RoleGridOps:
		return true
	default:
		return false
	}
}

// FilterUnprivileged returns groups with privileged role names removed.
func FilterUnprivileged(groups []string) []string {
	out := make([]string, 0, len(groups))
	for _, group := range groups {
		if IsPrivilegedRole(group) {
			continue
		}
		out = append(out, group)
	}
	return out
}

// PrivilegedEligible returns the privileged role names present in groups,
// in first-seen order, without duplicates.
func PrivilegedEligible(groups []string) []string {
	out := make([]string, 0, 3)
	seen := make(map[string]bool, 3)
	for _, group := range groups {
		if !IsPrivilegedRole(group) || seen[group] {
			continue
		}
		seen[group] = true
		out = append(out, group)
	}
	return out
}

// AgentCommandAllowed reports whether name is on the cloud-agent allowlist.
func AgentCommandAllowed(name string) bool {
	for _, allowed := range agentAllow {
		if allowed == name {
			return true
		}
	}
	return false
}

// AgentAllowlist returns a copy of the cloud-agent allowlist, which the grid
// binds to each managed agent it places.
func AgentAllowlist() []string {
	return append([]string(nil), agentAllow...)
}

func containsRole(roles []string, role string) bool {
	for _, item := range roles {
		if item == role {
			return true
		}
	}
	return false
}
