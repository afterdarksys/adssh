package i18n

import (
	"fmt"
	"sync"
)

var (
	registry = make(map[string]map[string]string)
	mu       sync.RWMutex
	currLang = "en"
)

// Load translates key-value pairs into the given language
func Load(lang string, dict map[string]string) {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := registry[lang]; !ok {
		registry[lang] = make(map[string]string)
	}
	for k, v := range dict {
		registry[lang][k] = v
	}
}

// SetLang sets the current active language
func SetLang(lang string) {
	mu.Lock()
	defer mu.Unlock()
	currLang = lang
}

// T translates a key into the active language, with optional formatting arguments
func T(key string, args ...interface{}) string {
	mu.RLock()
	defer mu.RUnlock()

	var template string
	if langDict, ok := registry[currLang]; ok {
		if val, ok := langDict[key]; ok {
			template = val
		}
	}

	// Fallback to "en" if not found in current language
	if template == "" && currLang != "en" {
		if enDict, ok := registry["en"]; ok {
			if val, ok := enDict[key]; ok {
				template = val
			}
		}
	}

	// Ultimate fallback to key itself
	if template == "" {
		template = key
	}

	if len(args) > 0 {
		return fmt.Sprintf(template, args...)
	}
	return template
}
