package security

import (
	"sort"
	"strings"
)

// Capability group identifiers. A capability names a CLASS of operation that a
// governed Starlark builtin performs (touching the network, the filesystem, a
// database, the process table, ...). Policies gate whole classes at once via
// input.capabilities instead of enumerating individual builtin names.
//
// These are deliberately coarse and stable: adding a builtin should map onto an
// existing capability whenever possible so operators' policies keep working.
const (
	CapNet          = "net"
	CapTCP          = "tcp"
	CapRegex        = "regex"
	CapStrings      = "strings"
	CapDatabases    = "databases"
	CapFileops      = "fileops"
	CapProc         = "proc"
	CapStdio        = "stdio"
	CapCrypto       = "crypto"
	CapData         = "data"
	CapCloud        = "cloud"
	CapK8s          = "k8s"
	CapContainers   = "containers"
	CapSecrets      = "secrets"
	CapSecurity     = "security"
	CapVCS          = "vcs"
	CapNotify       = "notify"
	CapTemplate     = "template"

	// CapUnclassified tags a starlark.* builtin path that no rule below matches.
	// It is a FAIL-CLOSED hook: a strict policy can deny
	// `input.capabilities[_] == "unclassified"` so a newly added builtin that
	// nobody classified cannot slip through an otherwise capability-scoped
	// allow-list. The allow-all default policy is unaffected.
	CapUnclassified = "unclassified"

	// starlarkPrefix is the path prefix govern.go stamps on every wrapped
	// Starlark builtin (GovernStarlarkGlobals uses "starlark."+name). Commands
	// without it are shell-layer commands (external binaries, mvdan builtins)
	// and are intentionally NOT capability-classified — they keep today's
	// name-based gating.
	starlarkPrefix = "starlark."
)

// nsCapabilities maps a Starlark top-level namespace (the first path segment
// after "starlark.") to its capabilities. The "sys" namespace is refined
// per-function in ClassifyCapabilities because it mixes classes (exec vs env vs
// file I/O). Cloud provider namespaces all fold into CapCloud.
var nsCapabilities = map[string][]string{
	"net":        {CapNet, CapTCP},
	"re":         {CapRegex},
	"db":         {CapDatabases},
	"fs":         {CapFileops},
	"crypto":     {CapCrypto},
	"data":       {CapData},
	"cloud":      {CapCloud},
	"aws":        {CapCloud},
	"gcp":        {CapCloud},
	"azure":      {CapCloud},
	"oci":        {CapCloud},
	"k8s":        {CapK8s},
	"docker":     {CapContainers},
	"containers": {CapContainers},
	"secrets":    {CapSecrets, CapSecurity},
	"sec":        {CapSecurity},
	"vcs":        {CapVCS},
	"notify":     {CapNotify},
	"template":   {CapTemplate},
	"i18n":       {CapTemplate},
	"str":        {CapStrings},
	"expect":     {CapProc, CapStdio},
}

// ClassifyCapabilities returns the capability groups a governed command touches.
//
// It returns nil for any command that is not a governed Starlark builtin (i.e.
// does not carry the "starlark." path prefix): external binaries and shell
// builtins are gated by name exactly as before, so this is additive and cannot
// change their behavior.
//
// For a "starlark.<ns>[.<fn>...]" path it returns the sorted, de-duplicated
// capabilities for that namespace, refining the "sys" namespace per function. A
// starlark.* path that matches no rule returns ["unclassified"] so a strict
// policy has a fail-closed hook (see CapUnclassified).
func ClassifyCapabilities(command string) []string {
	if !strings.HasPrefix(command, starlarkPrefix) {
		return nil
	}
	rest := strings.TrimPrefix(command, starlarkPrefix)
	if rest == "" {
		return []string{CapUnclassified}
	}
	parts := strings.Split(rest, ".")
	ns := parts[0]

	if ns == "sys" {
		fn := ""
		if len(parts) > 1 {
			fn = parts[1]
		}
		return dedupeSorted(sysCapabilities(fn))
	}

	if caps, ok := nsCapabilities[ns]; ok {
		return dedupeSorted(caps)
	}
	return []string{CapUnclassified}
}

// sysCapabilities classifies the "sys" namespace, whose functions span several
// classes: process execution/plugin loading (proc/stdio), environment access
// (stdio), and file I/O (fileops). An unrecognised sys.* function is stdio
// (the least-privileged of the namespace) rather than unclassified, since every
// sys builtin is at minimum a session-I/O operation.
func sysCapabilities(fn string) []string {
	switch fn {
	case "read_file", "write_file":
		return []string{CapFileops}
	case "exec_cmd", "exec_async", "exec_json", "parallel", "load_plugin", "load_plugins", "load_agent":
		return []string{CapProc, CapStdio}
	case "register_command", "register_completer":
		return []string{CapStdio}
	case "getenv", "setenv", "":
		return []string{CapStdio}
	default:
		return []string{CapStdio}
	}
}

func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
