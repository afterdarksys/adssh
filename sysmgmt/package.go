package sysmgmt

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// RunPackage acts as the virtual binary for "package".
// Usage: package [install|remove|update|list] <pkg>
func RunPackage(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: package [install|remove|update|list] <name>")
	}

	action := args[1]
	pkg := ""
	if len(args) > 2 {
		pkg = strings.Join(args[2:], " ")
	}

	manager, err := detectPackageManager()
	if err != nil {
		return err
	}

	var cmdArgs []string
	switch action {
	case "install":
		if pkg == "" {
			return fmt.Errorf("package install requires a package name")
		}
		cmdArgs = getInstallArgs(manager, pkg)
	case "remove":
		if pkg == "" {
			return fmt.Errorf("package remove requires a package name")
		}
		cmdArgs = getRemoveArgs(manager, pkg)
	case "update":
		cmdArgs = getUpdateArgs(manager)
	case "list":
		cmdArgs = getListArgs(manager)
	default:
		return fmt.Errorf("unsupported action: %s", action)
	}

	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	// Route output directly to the PTY foreground if running under mvdan/sh?
	// But as a virtual binary returned by interceptor, mvdan/sh will wire it?
	// Actually, the interceptor expects an error return, but wait:
	// How does a virtual binary output to the shell?
	// The interceptor executes the command in place of the runner.
	// But `interp.ExecHandler` expects the handler to DO the IO wiring!
	// Let's wire to os.Stdout/os.Stderr for now. (Or we can just execute via mvdan/sh)
	// Wait, we can just return a generated string and have the interceptor parse it?
	// For simplicity, we just run exec.Command and return its output as an error if it fails.

	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		fmt.Print(string(out))
	}
	if err != nil {
		return fmt.Errorf("package execution failed: %v", err)
	}
	return nil
}

func detectPackageManager() (string, error) {
	managers := []string{"apt-get", "dnf", "yum", "apk", "brew"}
	for _, m := range managers {
		if _, err := exec.LookPath(m); err == nil {
			return m, nil
		}
	}
	return "", fmt.Errorf("no supported package manager found on this system")
}

func getInstallArgs(manager, pkg string) []string {
	switch manager {
	case "apt-get":
		return []string{"apt-get", "install", "-y", pkg}
	case "dnf":
		return []string{"dnf", "install", "-y", pkg}
	case "yum":
		return []string{"yum", "install", "-y", pkg}
	case "apk":
		return []string{"apk", "add", pkg}
	case "brew":
		return []string{"brew", "install", pkg}
	}
	return nil
}

func getRemoveArgs(manager, pkg string) []string {
	switch manager {
	case "apt-get":
		return []string{"apt-get", "remove", "-y", pkg}
	case "dnf", "yum":
		return []string{"dnf", "remove", "-y", pkg}
	case "apk":
		return []string{"apk", "del", pkg}
	case "brew":
		return []string{"brew", "uninstall", pkg}
	}
	return nil
}

func getUpdateArgs(manager string) []string {
	switch manager {
	case "apt-get":
		return []string{"apt-get", "update"}
	case "dnf", "yum":
		return []string{"dnf", "check-update"}
	case "apk":
		return []string{"apk", "update"}
	case "brew":
		return []string{"brew", "update"}
	}
	return nil
}

func getListArgs(manager string) []string {
	switch manager {
	case "apt-get":
		return []string{"dpkg", "-l"}
	case "dnf", "yum":
		return []string{"dnf", "list", "installed"}
	case "apk":
		return []string{"apk", "info"}
	case "brew":
		return []string{"brew", "list"}
	}
	return nil
}
