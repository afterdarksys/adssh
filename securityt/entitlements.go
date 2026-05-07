package security

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"sync"
)

type EntitlementsConfig struct {
	Groups map[string][]string `yaml:"groups"`
	Users  map[string][]string `yaml:"users"`
	Menus  map[string]string   `yaml:"menus"`
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
			// Fail-closed: If no entitlements file exists, deny everything.
			return fmt.Errorf("no entitlements file found at %s: strict default-deny enforced", path)
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

// IsAuthorized checks if the user or their principals are authorized to run a virtual binary or custom command.
// If the command is not listed in any entitlement, access is denied (Default-Deny).
// If no entitlements file was loaded, it allows everything.
func IsAuthorized(user string, principals []string, command string) bool {
	entitlementsMu.RLock()
	defer entitlementsMu.RUnlock()

	// If no config loaded, default deny (fail-closed)
	if len(entitlements.Groups) == 0 && len(entitlements.Users) == 0 {
		return false
	}

	// 1. Check User-specific entitlements
	if allowedCmds, ok := entitlements.Users[user]; ok {
		for _, cmd := range allowedCmds {
			if cmd == command || cmd == "*" {
				return true
			}
		}
	}

	// 2. Check Principal-specific entitlements
	for _, principal := range principals {
		if allowedCmds, ok := entitlements.Groups[principal]; ok {
			for _, cmd := range allowedCmds {
				if cmd == command || cmd == "*" {
					return true
				}
			}
		}
	}

	return false
}

// GetMenuForUser checks if a specific menu YAML file is assigned to the user or their groups.
func GetMenuForUser(user string, principals []string) string {
	entitlementsMu.RLock()
	defer entitlementsMu.RUnlock()

	if len(entitlements.Menus) == 0 {
		return ""
	}

	// 1. Check User-specific menu
	if menuPath, ok := entitlements.Menus[user]; ok {
		return menuPath
	}

	// 2. Check Principal-specific menu
	for _, principal := range principals {
		if menuPath, ok := entitlements.Menus[principal]; ok {
			return menuPath
		}
	}

	return ""
}
