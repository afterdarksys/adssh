package config

import (
	"os"
	"path/filepath"
)

// XDGConfigHome returns the adssh config directory under $XDG_CONFIG_HOME/adssh.
// Falls back to ~/.adssh if XDG_CONFIG_HOME is not set.
// Maintains backward compatibility: if ~/.adssh/ exists and XDG_CONFIG_HOME is
// not set, ~/.adssh/ is returned so existing installations are unaffected.
func XDGConfigHome() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "adssh")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".adssh")
}

// XDGDataHome returns the adssh data directory under $XDG_DATA_HOME/adssh.
// Falls back to ~/.adssh if XDG_DATA_HOME is not set.
func XDGDataHome() string {
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "adssh")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".adssh")
}

// XDGCacheHome returns the adssh cache directory under $XDG_CACHE_HOME/adssh.
// Falls back to ~/.adssh/cache if XDG_CACHE_HOME is not set.
func XDGCacheHome() string {
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, "adssh")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".adssh", "cache")
}
