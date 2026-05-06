package security

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"os/user"
	"sync"
)

type EntitlementsConfig struct {
	Groups map[string][]string `yaml:"groups"`
	Users  map[string][]string `yaml:"users"`
}

var (
	entitlements   EntitlementsConfig
	entitlementsMu sync.RWMutex
)

// LoadEntitlements reads the RBAC yaml configuration
func LoadEntitlements(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// If no file exists, default to fully open (or fully closed, depending on security posture)
			// For this prototype, we'll assume no file means open access for ease of use,
			// but in an enterprise setting, it should default to closed.
			return nil
		}
		return err
	}

	entitlementsMu.Lock()
	defer entitlementsMu.Unlock()

	err = yaml.Unmarshal(data, &entitlements)
	if err != nil {
		return fmt.Errorf("failed to parse entitlements: %v", err)
	}
	return nil
}

// IsAuthorized checks if the current OS user is authorized to run a virtual binary or custom command.
// If the command is not listed in any entitlement, access is denied (Default-Deny).
// If no entitlements file was loaded, it allows everything.
func IsAuthorized(command string) bool {
	entitlementsMu.RLock()
	defer entitlementsMu.RUnlock()

	// If no config loaded, allow all
	if len(entitlements.Groups) == 0 && len(entitlements.Users) == 0 {
		return true
	}

	currentUser, err := user.Current()
	if err != nil {
		return false
	}

	// 1. Check User-specific entitlements
	if allowedCmds, ok := entitlements.Users[currentUser.Username]; ok {
		for _, cmd := range allowedCmds {
			if cmd == command || cmd == "*" {
				return true
			}
		}
	}

	// 2. Check Group-specific entitlements
	groupIDs, err := currentUser.GroupIds()
	if err == nil {
		for _, gid := range groupIDs {
			g, err := user.LookupGroupId(gid)
			if err != nil {
				continue
			}
			if allowedCmds, ok := entitlements.Groups[g.Name]; ok {
				for _, cmd := range allowedCmds {
					if cmd == command || cmd == "*" {
						return true
					}
				}
			}
		}
	}

	return false
}
