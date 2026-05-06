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
//	ADSSH_POLICY=/path         Path to Rego policy file     (default: ~/.adssh/policy.rego)
type AppConfig struct {
	Restricted         bool
	ServeAddr          string
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
}

// LoadFromEnv populates an AppConfig from ADSSH_* environment variables,
// filling in well-known defaults for any value not set.
func LoadFromEnv() AppConfig {
	home, _ := os.UserHomeDir()
	adsshDir := filepath.Join(home, ".adssh")

	cfg := AppConfig{
		Restricted:         isTruthy(os.Getenv("ADSSH_RESTRICTED")),
		ServeAddr:          os.Getenv("ADSSH_SERVE"),
		EntitlementsPath:   os.Getenv("ADSSH_ENTITLEMENTS"),
		PolicyPath:         envOr("ADSSH_POLICY", filepath.Join(adsshDir, "policy.rego")),
		AuditLogPath:       envOr("ADSSH_AUDIT_LOG", filepath.Join(adsshDir, "audit.log")),
		HistoryFile:        envOr("ADSSH_HISTORY", filepath.Join(adsshDir, "history")),
		HostKeyPath:        envOr("ADSSH_HOST_KEY", filepath.Join(adsshDir, "host_key")),
		AuthorizedKeysPath: envOr("ADSSH_AUTHORIZED_KEYS", filepath.Join(adsshDir, "authorized_keys")),
		ProfilePath:        envOr("ADSSH_PROFILE", filepath.Join(home, ".adsshprofile")),
		RCPath:             envOr("ADSSH_RC", filepath.Join(home, ".adsshrc")),
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
