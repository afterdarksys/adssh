package security

import (
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

type EntitlementsConfig struct {
	Groups map[string][]string `yaml:"groups"`
	Users  map[string][]string `yaml:"users"`
	Menus  map[string]string   `yaml:"menus"`
}

// LoadEntitlements reads the RBAC yaml configuration
func (e *Engine) LoadEntitlements(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Fail-closed: If no entitlements file exists, deny everything.
			return fmt.Errorf("no entitlements file found at %s: strict default-deny enforced", path)
		}
		return err
	}

	e.entitlementsMu.Lock()
	defer e.entitlementsMu.Unlock()

	err = yaml.Unmarshal(data, &e.entitlements)
	if err != nil {
		return fmt.Errorf("failed to parse entitlements: %v", err)
	}
	e.entitlementsLoaded = true
	return nil
}

func (e *Engine) hasEntitlements() bool {
	e.entitlementsMu.RLock()
	defer e.entitlementsMu.RUnlock()
	return e.entitlementsLoaded
}

// IsAuthorized checks if the user or their principals are authorized to run a virtual binary or custom command.
// If the command is not listed in any entitlement, access is denied (Default-Deny).
// If no entitlements file was loaded, it allows everything.
func (e *Engine) IsAuthorized(user string, principals []string, command string) bool {
	e.entitlementsMu.RLock()
	defer e.entitlementsMu.RUnlock()

	// If no config loaded, default deny (fail-closed)
	if len(e.entitlements.Groups) == 0 && len(e.entitlements.Users) == 0 {
		return false
	}

	// 1. Check User-specific entitlements
	if allowedCmds, ok := e.entitlements.Users[user]; ok {
		for _, cmd := range allowedCmds {
			if cmd == command || cmd == "*" {
				return true
			}
		}
	}

	// 2. Check Principal-specific entitlements
	for _, principal := range principals {
		if allowedCmds, ok := e.entitlements.Groups[principal]; ok {
			for _, cmd := range allowedCmds {
				if cmd == command || cmd == "*" {
					return true
				}
			}
		}
	}

	return false
}

// EntitlementsHeld returns the entitlement entries that apply to user and
// principals, as "user:<name>" and "group:<name>", sorted. It is empty when
// no entitlements file is loaded.
func (e *Engine) EntitlementsHeld(user string, principals []string) []string {
	e.entitlementsMu.RLock()
	defer e.entitlementsMu.RUnlock()
	seen := map[string]bool{}
	if _, ok := e.entitlements.Users[user]; ok && user != "" {
		seen["user:"+user] = true
	}
	for _, principal := range principals {
		if _, ok := e.entitlements.Groups[principal]; ok {
			seen["group:"+principal] = true
		}
	}
	return sortedKeys(seen)
}

// EntitlementsGranting returns the entitlement entries whose allow-list
// names command or "*", in the same form and order as EntitlementsHeld.
func (e *Engine) EntitlementsGranting(command string) []string {
	e.entitlementsMu.RLock()
	defer e.entitlementsMu.RUnlock()
	seen := map[string]bool{}
	for kind, entries := range map[string]map[string][]string{"user:": e.entitlements.Users, "group:": e.entitlements.Groups} {
		for name, cmds := range entries {
			for _, cmd := range cmds {
				if cmd == command || cmd == "*" {
					seen[kind+name] = true
					break
				}
			}
		}
	}
	return sortedKeys(seen)
}

// EntitledCommands returns the commands the entries held by user and
// principals list, sorted. "*" is returned as is.
func (e *Engine) EntitledCommands(user string, principals []string) []string {
	e.entitlementsMu.RLock()
	defer e.entitlementsMu.RUnlock()
	seen := map[string]bool{}
	add := func(cmds []string) {
		for _, cmd := range cmds {
			seen[cmd] = true
		}
	}
	if user != "" {
		add(e.entitlements.Users[user])
	}
	for _, principal := range principals {
		add(e.entitlements.Groups[principal])
	}
	return sortedKeys(seen)
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// GetMenuForUser checks if a specific menu YAML file is assigned to the user or their groups.
func (e *Engine) GetMenuForUser(user string, principals []string) string {
	e.entitlementsMu.RLock()
	defer e.entitlementsMu.RUnlock()

	if len(e.entitlements.Menus) == 0 {
		return ""
	}

	// 1. Check User-specific menu
	if menuPath, ok := e.entitlements.Menus[user]; ok {
		return menuPath
	}

	// 2. Check Principal-specific menu
	for _, principal := range principals {
		if menuPath, ok := e.entitlements.Menus[principal]; ok {
			return menuPath
		}
	}

	return ""
}

// HasExplicitEntitlement reports whether the user entry itself names command.
// A "*" wildcard and group entries do not count: it is for grants that must
// be deliberate per principal, such as admin.snoop.rw for an admin key.
func (e *Engine) HasExplicitEntitlement(user, command string) bool {
	if user == "" || command == "" || command == "*" {
		return false
	}
	e.entitlementsMu.RLock()
	defer e.entitlementsMu.RUnlock()
	for _, cmd := range e.entitlements.Users[user] {
		if cmd == command {
			return true
		}
	}
	return false
}
