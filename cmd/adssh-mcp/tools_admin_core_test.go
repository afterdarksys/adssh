//go:build !ee

package main

import (
	"strings"
	"sync"
	"testing"

	"github.com/afterdarksys/adssh/engine"
	"github.com/mark3labs/mcp-go/server"
)

// The core build has the identity tools and no admin_* tools.
func TestCoreRegistersNoAdminTools(t *testing.T) {
	eng, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	s := server.NewMCPServer("test", "0", server.WithToolCapabilities(false))
	registerGovernedAdminTools(s, &sync.Mutex{}, eng, mcpAgentConfig{})
	tools := s.ListTools()
	for name := range tools {
		if strings.HasPrefix(name, "admin_") {
			t.Errorf("core build registers enterprise tool %s", name)
		}
	}
	for _, name := range []string{"identity_status", "identity_device_login"} {
		if _, ok := tools[name]; !ok {
			t.Errorf("core build lacks %s", name)
		}
	}
}
