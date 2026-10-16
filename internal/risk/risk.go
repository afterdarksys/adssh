// Package risk holds the destructive-command classifier shared by the MCP
// run_shell dry-run gate and the REPL's danger highlighting and confirm
// preview. It is a substring heuristic: it flags, it never authorizes.
package risk

import "strings"

var destructiveFragments = []string{
	"rm -", "rm ", " rmdir ", "delete", "destroy", "terminate",
	"kubectl delete", "terraform apply", "terraform destroy", "tofu apply", "tofu destroy",
	"docker rm", "docker rmi", "git push --force", "chmod 777",
}

// LooksDestructive reports whether command contains a destructive fragment.
func LooksDestructive(command string) bool {
	lower := strings.ToLower(command)
	for _, fragment := range destructiveFragments {
		if strings.Contains(lower, fragment) {
			return true
		}
	}
	return false
}

// ShellCommandClass is the risk class of a shell command: "destructive" or
// "mutable".
func ShellCommandClass(command string) string {
	if LooksDestructive(command) {
		return "destructive"
	}
	return "mutable"
}
