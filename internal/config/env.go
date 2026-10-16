package config

import (
	"os"
	"path/filepath"
	"strings"
)

// AppConfig holds all runtime configuration for adssh.
// Values are populated from environment variables first, then overridden
// by any CLI flags provided at startup.
//
// Environment variables:
//
//	ADSSH_RESTRICTED=1         Enable restricted (sandboxed) mode
//	ADSSH_SERVE=:2222          Start SSH server on this address
//	ADSSH_ENTITLEMENTS=/path   Path to RBAC entitlements YAML
//	ADSSH_AUDIT_LOG=/path      Path to audit log file       (default: ~/.adssh/audit.log)
//	ADSSH_HISTORY=/path        Path to readline history     (default: ~/.adssh/history)
//	ADSSH_HOST_KEY=/path       Path to SSH host key         (default: ~/.adssh/host_key)
//	ADSSH_AUTHORIZED_KEYS=/p   Path to SSH authorized_keys  (default: ~/.adssh/authorized_keys)
//	ADSSH_PROFILE=/path        Path to login profile script (default: ~/.adsshprofile)
//	ADSSH_RC=/path             Path to interactive RC script (default: ~/.adsshrc)
//	ADSSH_GIT_PROMPT=1         Show the git branch for \g in the prompt (default off;
//	                           1/true/yes/on). Read by the REPL. Ignored in restricted
//	                           mode and SSH sessions.
//	ADSSH_POLICY=/path         Path to Rego policy file     (default: ~/.adssh/policy.rego)
//	ADSSH_AUDIT_URL=url        Webhook URL for remote SIEM logging. Must be https and
//	                           needs ADSSH_AUDIT_LOG; the host is resolved and checked
//	                           at send time (private hosts need ADSSH_CALLBACK_ALLOW_PRIVATE).
//	ADSSH_AUDIT_TOKEN=token    Bearer token for the webhook URL
//	ADSSH_CONTROLPLANE_URL=url Control-plane origin for `identity device login`
//	                           (https://host[:port], no path). Unset fails closed.
//	ADSSH_OIDC_ISSUER=iss      Issuer for `identity oidc import` (default and login
//	                           providers). Token iss must equal it. Unset fails closed.
//	ADSSH_OIDC_JWKS_URL=url    https JWKS URL for the default and login providers
//	ADSSH_OIDC_ADMIN_ISSUER=i  Issuer for `identity oidc import --provider admin`
//	ADSSH_OIDC_ADMIN_JWKS_URL= https JWKS URL for the admin provider
//	ADSSH_OIDC_LOGIN_AUDIENCE= aud for the default and login providers. Unset fails closed.
//	ADSSH_OIDC_ADMIN_AUDIENCE= aud for --provider admin. Unset fails closed; must
//	                           differ from the login audience.
//	ADSSH_CALLBACK_ALLOW_PRIVATE=1  Allow RFC1918, 100.64/10, and fc00::/7 hosts for
//	                           control-plane, JWKS, webhook, and approval URLs
//	                           (default off; 1/true/yes). Metadata stays blocked.
//	ADSSH_AGENT_SERVE=addr     Start instrumentation-agent HTTP listener on addr
//	                           (e.g. 127.0.0.1:7777 — localhost or behind TLS)
//	ADSSH_AGENT_TOKEN=token    Bearer token the instrumentation agent requires
//	                           (no token => agent refuses to start; fail closed)
//	ADSSH_AGENT_TASKS=/path    Instrumentation task allowlist YAML
//	                           (default: ~/.adssh/instrument-tasks.yaml)
//	ADSSH_SAH=1                Enable the sah/1 stdio subcommand (default off).
//	                           Only 1/true/yes turn it on. Unset, "on", and any
//	                           other value stay off.
//	ADSSH_GUARD=off            SSH listener jail switch. Stored raw.
//	                           off forces the jail off. on forces it on.
//	                           Unset follows guard.yaml. Any other value fails closed.
//	ADSSH_SSH_PERMIT_ROOT=1    Allow SSH logins as root or any uid-0 name (default off).
//	                           Only 1/true/yes turn it on.
//	ADSSH_GUARD_CONFIG=/path  Jail config (default: ~/.adssh/guard.yaml)
//	ADSSH_GUARD_STATE=/path   Ban file (default: ~/.adssh/guard-state.json)
//	ADSSH_ADMIN_KEYS=/path    0600 name=key file for `admin serve`. A named key can
//	                          approve, deny, and unban as that name.
type AppConfig struct {
	Restricted         bool
	SAHEnabled         bool
	ServeAddr          string
	SSHPermitRoot      bool
	ScriptPath         string
	IsLoginShell       bool
	EntitlementsPath   string
	PolicyPath         string
	AuditLogPath       string
	HistoryFile        string
	HostKeyPath        string
	AuthorizedKeysPath string
	ProfilePath        string
	RCPath             string
	AuditURL           string
	AuditToken         string
	AgentServeAddr     string
	AgentToken         string
	AgentTasksPath     string
	GuardSwitch        string
	GuardConfigPath    string
	GuardStatePath     string
}

// LoadFromEnv populates an AppConfig from ADSSH_* environment variables,
// filling in well-known defaults for any value not set.
// Path defaults follow XDG Base Directory spec when XDG_* vars are set;
// otherwise ~/.adssh/ is used for backward compatibility.
func LoadFromEnv() AppConfig {
	home, _ := os.UserHomeDir()
	cfgDir := XDGConfigHome() // ~/.adssh or $XDG_CONFIG_HOME/adssh

	cfg := AppConfig{
		Restricted:         isTruthy(os.Getenv("ADSSH_RESTRICTED")),
		SAHEnabled:         isTruthy(os.Getenv("ADSSH_SAH")),
		ServeAddr:          os.Getenv("ADSSH_SERVE"),
		SSHPermitRoot:      isTruthy(os.Getenv("ADSSH_SSH_PERMIT_ROOT")),
		EntitlementsPath:   os.Getenv("ADSSH_ENTITLEMENTS"),
		PolicyPath:         envOr("ADSSH_POLICY", filepath.Join(cfgDir, "policy.rego")),
		AuditLogPath:       envOr("ADSSH_AUDIT_LOG", filepath.Join(cfgDir, "audit.log")),
		HistoryFile:        envOr("ADSSH_HISTORY", filepath.Join(cfgDir, "history")),
		HostKeyPath:        envOr("ADSSH_HOST_KEY", filepath.Join(cfgDir, "host_key")),
		AuthorizedKeysPath: envOr("ADSSH_AUTHORIZED_KEYS", filepath.Join(cfgDir, "authorized_keys")),
		ProfilePath:        envOr("ADSSH_PROFILE", filepath.Join(home, ".adsshprofile")),
		RCPath:             envOr("ADSSH_RC", filepath.Join(home, ".adsshrc")),
		AuditURL:           os.Getenv("ADSSH_AUDIT_URL"),
		AuditToken:         os.Getenv("ADSSH_AUDIT_TOKEN"),
		AgentServeAddr:     os.Getenv("ADSSH_AGENT_SERVE"),
		AgentToken:         os.Getenv("ADSSH_AGENT_TOKEN"),
		AgentTasksPath:     envOr("ADSSH_AGENT_TASKS", filepath.Join(cfgDir, "instrument-tasks.yaml")),
		GuardSwitch:        os.Getenv("ADSSH_GUARD"),
		GuardConfigPath:    envOr("ADSSH_GUARD_CONFIG", filepath.Join(cfgDir, "guard.yaml")),
		GuardStatePath:     envOr("ADSSH_GUARD_STATE", filepath.Join(cfgDir, "guard-state.json")),
	}
	return cfg
}

func envOr(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func isTruthy(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "1" || s == "true" || s == "yes"
}
