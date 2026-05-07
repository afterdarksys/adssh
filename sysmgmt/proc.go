package sysmgmt

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// RunProc acts as the virtual binary for "proc".
// Usage: proc [get|set] <path> [value]
func RunProc(ctx context.Context, args []string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("adssh: proc subsystem is only supported natively on Linux. Found: %s", runtime.GOOS)
	}

	if len(args) < 3 {
		return fmt.Errorf("usage: proc [get|set] <path> [value]")
	}

	action := args[1]
	path := args[2]

	// Basic security check to prevent directory traversal outside of /proc
	if strings.Contains(path, "..") {
		return fmt.Errorf("proc: directory traversal is not allowed")
	}

	fullPath := filepath.Join("/proc", path)

	switch action {
	case "get":
		data, err := os.ReadFile(fullPath)
		if err != nil {
			return fmt.Errorf("proc get failed: %v", err)
		}
		fmt.Print(string(data))
		return nil

	case "set":
		if len(args) < 4 {
			return fmt.Errorf("proc set requires a value")
		}
		value := strings.Join(args[3:], " ")
		err := os.WriteFile(fullPath, []byte(value+"\n"), 0644)
		if err != nil {
			return fmt.Errorf("proc set failed: %v", err)
		}
		fmt.Printf("proc: updated %s\n", fullPath)
		return nil

	default:
		return fmt.Errorf("proc: unsupported action '%s'. Use 'get' or 'set'", action)
	}
}
