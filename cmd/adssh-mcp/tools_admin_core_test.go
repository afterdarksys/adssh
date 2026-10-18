//go:build !ee

package main

import (
	"strings"
	"sync"
	"testing"

	"github.com/afterdarksys/adssh/engine"
	"github.com/mark3labs/mcp-go/server"
)

// The core build has identity_status and no admin_* tools and no
// identity_device_login (enterprise).
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
	if _, ok := tools["identity_status"]; !ok {
		t.Error("core build lacks identity_status")
	}
	if _, ok := tools["identity_device_login"]; ok {
		t.Error("core build registers enterprise tool identity_device_login")
	}
}
