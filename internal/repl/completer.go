package repl

import (
	"github.com/afterdarksys/adssh/internal/starlarkext"
	"github.com/afterdarksys/adssh/security"
	"os"
	"path/filepath"
	"strings"

	"go.starlark.net/starlark"
)

// adsshCompleter implements readline.AutoCompleter.
// It completes:
//   - First word: virtual binaries, shell builtins, Starlark namespace names,
//     and dynamically registered custom commands / plugin names.
//   - Starlark namespace.method (e.g. "sys.ge" → "sys.getenv")
//   - mirror / cmdgen subcommands
//   - vbin subcommands (stty, history, fc, ...)
//   - History-prefix suggestions
//   - File paths for all other arguments
type adsshCompleter struct {
	globals starlark.StringDict
	history *[]string
}

var shellBuiltins = []string{
	"cd", "export", "exit", "quit", "echo", "ls", "cat", "grep",
	"find", "which", "env", "pwd", "mkdir", "rm", "cp", "mv",
	"chmod", "chown", "ps", "kill", "jobs", "bg", "fg",
	// extended builtins
	"alias", "unalias", "source", ".", "set", "read", "trap",
	"pushd", "popd", "dirs", "type", "command", "time", "disown",
	"fc", "history",
}

var starlarkNamespaces = []string{
	"sys", "net", "crypto", "data", "re", "sec", "i18n", "cloud", "plugins",
	"aws", "oci", "gcp", "git", "github", "containers",
	"az", "k8s", "docker", "secrets", "db", "notify", "expect", "template",
}

// starlarkNamespaceKeys maps namespace → list of method/sub-namespace names.
var starlarkNamespaceKeys = map[string][]string{
	"sys":    {"getenv", "setenv", "load_plugin", "read_file", "write_file", "exec_cmd", "exec_async", "exec_json", "register_command"},
	"net":    {"tcp_send", "http_get"},
	"crypto": {"md5", "sha256"},
	"data":   {"json_parse", "json_dump", "yaml_parse", "yaml_dump"},
	"re":     {"match", "pcre_match"},
	"sec":    {"audit", "is_restricted", "file_hash"},
	"i18n":   {"load", "set_lang", "T"},
	"cloud":  {"gen"},
	// Cloud providers
	"aws":         {"ec2", "s3", "ecs", "lambda"},
	"aws.ec2":     {"list_instances", "start_instance", "stop_instance", "terminate_instance"},
	"aws.s3":      {"list_buckets", "get_object", "put_object", "delete_object"},
	"aws.ecs":     {"list_clusters", "list_services"},
	"aws.lambda":  {"list_functions", "invoke"},
	"oci":         {"compute", "storage"},
	"oci.compute": {"list_instances", "start_instance", "stop_instance"},
	"oci.storage": {"list_buckets", "get_object", "put_object", "delete_object"},
	"gcp":         {"compute", "storage"},
	"gcp.compute": {"list_instances", "start_instance", "stop_instance"},
	"gcp.storage": {"list_buckets", "get_object", "put_object", "delete_object"},
	// VCS
	"git":    {"clone", "open", "status", "add", "commit", "push", "pull", "log"},
	"github": {"list_repos", "list_prs", "create_pr", "merge_pr", "list_issues", "create_issue", "close_issue", "create_release", "list_workflows", "trigger_workflow"},
	// Containers
	"containers": {"exec", "list", "audit", "replay", "clean"},
	// Azure
	"az": {"rg", "vm", "storage", "aks"},
	// Kubernetes
	"k8s": {"pods", "deployments", "services", "namespaces", "configmaps", "nodes", "events"},
	// Docker
	"docker": {"ps", "inspect", "logs", "images", "networks", "volumes"},
	// Secrets
	"secrets": {"vault", "aws", "az", "gcp"},
	// Database
	"db": {"postgres", "mysql", "redis"},
	// Notifications
	"notify": {"slack", "webhook", "pagerduty", "teams"},
	// Expect / template
	"expect":   {"spawn"},
	"template": {"render", "render_file"},
	// AWS sub-namespaces
	"aws.cloudwatch": {"get_metric", "list_alarms", "get_alarm_state"},
	"aws.route53":    {"list_zones", "list_records", "upsert_record", "delete_record"},
	// GCP sub-namespaces
	"gcp.gke":    {"list_clusters", "get_cluster"},
	"gcp.pubsub": {"list_topics", "publish", "list_subscriptions"},
	"gcp.run":    {"list_services", "get_service"},
}

var mirrorSubcmds = []string{"list", "view", "console", "kill"}
var cmdgenProviders = []string{"docker", "kubectl", "aws"}

// vbinSubcommands maps a vbin name to its recognized first-argument completions.
var vbinSubcommands = map[string][]string{
	"stty":     {"sane", "size", "echo", "-echo", "raw", "-raw", "rows", "cols"},
	"history":  {"-c", "-d"},
	"fc":       {"-l", "-e"},
	"mirror":   {"list", "view", "console", "kill"},
	"cmdgen":   {"docker", "kubectl", "aws"},
	"set":      {"-e", "+e", "-u", "+u", "-x", "+x", "-o", "+o"},
	"help":     {"list", "search", "categories", "examples"},
	"pick":     {"--query", "--index", "--json", "--non-interactive"},
	"nav":      {"--hidden", "--json", "--select", "--non-interactive"},
	"from":     {"json", "jsonl", "csv"},
	"to":       {"json", "jsonl", "csv", "table"},
	"why":      {"--json", "--"},
	"??":       {"--json"},
	"runbook":  {"list", "show", "run"},
	"par":      {"--jobs", "--"},
	"evidence": {"--session", "--change", "--since", "--until", "--out"},
	"lease":    {"--from", "--as", "--ttl", "--"},
	"elevate":  {"request", "status", "drop", "--for", "--reason"},
	"gateway":  {"start", "list", "stop", "--listen", "--target", "--name"},
}

// Do implements readline.AutoCompleter.
// length is the number of runes before pos that form the current token.
// Each element of newLine is the suffix to append (full candidate minus the already-typed prefix).
func (c *adsshCompleter) Do(line []rune, pos int) (newLine [][]rune, length int) {
	lineStr := string(line[:pos])

	// ── Starlark namespace.method completion ────────────────────────────────
	// Matches patterns like "sys.ge" or "x = sys.ge" anywhere in the line.
	if dotIdx := strings.LastIndex(lineStr, "."); dotIdx >= 0 {
		afterDot := lineStr[dotIdx+1:]
		beforeDot := lineStr[:dotIdx]

		// The namespace is the last whitespace-delimited token before the dot.
		parts := strings.Fields(beforeDot)
		var ns string
		if len(parts) > 0 {
			ns = parts[len(parts)-1]
		} else {
			ns = beforeDot
		}

		if keys, ok := starlarkNamespaceKeys[ns]; ok {
			var completions [][]rune
			for _, k := range keys {
				if strings.HasPrefix(k, afterDot) {
					completions = append(completions, []rune(k[len(afterDot):]))
				}
			}
			return completions, len(afterDot)
		}
	}

	words := strings.Fields(lineStr)
	endsWithSpace := len(lineStr) > 0 && lineStr[len(lineStr)-1] == ' '

	// ── First word: command completion ──────────────────────────────────────
	if len(words) == 0 || (len(words) == 1 && !endsWithSpace) {
		prefix := ""
		if len(words) == 1 {
			prefix = words[0]
		}
		return c.completeCommand(prefix)
	}

	cmd := words[0]
	argPrefix := ""
	completingArg := !endsWithSpace && len(words) >= 2
	if completingArg {
		argPrefix = words[len(words)-1]
	}

	// ── Check Custom Completers ─────────────────────────────────────────────
	// Prefer this session's own completers (stored in its globals dict), then
	// fall back to the deprecated process-global registry.
	var callable starlark.Callable
	var ok bool
	if c.globals != nil {
		if dict, dok := c.globals["__completers__"].(*starlark.Dict); dok {
			if v, found, _ := dict.Get(starlark.String(cmd)); found {
				callable, ok = v.(starlark.Callable)
			}
		}
	}
	if !ok {
		starlarkext.CompletersMu.RLock()
		callable, ok = starlarkext.CustomCompleters[cmd]
		starlarkext.CompletersMu.RUnlock()
	}

	if ok {
		thread := &starlark.Thread{Name: "completer-" + cmd}
		res, err := starlark.Call(thread, callable, starlark.Tuple{starlark.String(argPrefix), starlark.String(lineStr)}, nil)
		if err == nil {
			if list, ok := res.(*starlark.List); ok {
				var completions [][]rune
				iter := list.Iterate()
				defer iter.Done()
				var val starlark.Value
				for iter.Next(&val) {
					if s, ok := val.(starlark.String); ok {
						strVal := string(s)
						if strings.HasPrefix(strVal, argPrefix) {
							completions = append(completions, []rune(strVal[len(argPrefix):]))
						}
					}
				}
				return completions, len(argPrefix)
			}
		}
	}

	// ── mirror subcommands ───────────────────────────────────────────────────
	if cmd == "mirror" && len(words) <= 2 {
		var completions [][]rune
		for _, s := range mirrorSubcmds {
			if strings.HasPrefix(s, argPrefix) {
				completions = append(completions, []rune(s[len(argPrefix):]))
			}
		}
		return completions, len(argPrefix)
	}

	// ── cmdgen providers ─────────────────────────────────────────────────────
	if cmd == "cmdgen" && len(words) <= 2 {
		var completions [][]rune
		for _, s := range cmdgenProviders {
			if strings.HasPrefix(s, argPrefix) {
				completions = append(completions, []rune(s[len(argPrefix):]))
			}
		}
		return completions, len(argPrefix)
	}

	// ── Generic vbin subcommand completion ───────────────────────────────────
	if subs, ok := vbinSubcommands[cmd]; ok && len(words) <= 2 {
		var completions [][]rune
		for _, s := range subs {
			if strings.HasPrefix(s, argPrefix) {
				completions = append(completions, []rune(s[len(argPrefix):]))
			}
		}
		return completions, len(argPrefix)
	}

	// ── Default: file path completion ────────────────────────────────────────
	return c.completeFile(argPrefix)
}

// completeCommand returns suffix completions for the first word on the line.
func (c *adsshCompleter) completeCommand(prefix string) ([][]rune, int) {
	seen := make(map[string]bool)
	var candidates []string

	for _, vb := range security.ListVBins() {
		name := vb.Name()
		if !seen[name] {
			seen[name] = true
			candidates = append(candidates, name)
		}
	}
	for _, name := range shellBuiltins {
		if !seen[name] {
			seen[name] = true
			candidates = append(candidates, name)
		}
	}
	for _, name := range starlarkNamespaces {
		if !seen[name] {
			seen[name] = true
			candidates = append(candidates, name)
		}
	}

	// Dynamically registered custom commands
	if c.globals != nil {
		if dictVal, ok := c.globals["__custom_commands__"]; ok {
			if dict, ok := dictVal.(*starlark.Dict); ok {
				for _, kv := range dict.Items() {
					if name, ok := kv[0].(starlark.String); ok {
						s := string(name)
						if !seen[s] {
							seen[s] = true
							candidates = append(candidates, s)
						}
					}
				}
			}
		}
		// Plugin namespace names (so "plugins[" completes to plugin names)
		if pluginsVal, ok := c.globals["plugins"]; ok {
			if dict, ok := pluginsVal.(*starlark.Dict); ok {
				for _, kv := range dict.Items() {
					if name, ok := kv[0].(starlark.String); ok {
						s := "plugins[\"" + string(name) + "\"]"
						if !seen[s] {
							seen[s] = true
							candidates = append(candidates, s)
						}
					}
				}
			}
		}
	}

	// History-prefix suggestions (deduplicated, most recent first)
	if c.history != nil && len(prefix) > 2 {
		histSeen := make(map[string]bool)
		hist := *c.history
		for i := len(hist) - 1; i >= 0; i-- {
			entry := hist[i]
			// Use only the first word of each history entry for command completion
			firstWord := strings.Fields(entry)
			if len(firstWord) == 0 {
				continue
			}
			w := firstWord[0]
			if strings.HasPrefix(w, prefix) && !seen[w] && !histSeen[w] {
				histSeen[w] = true
				candidates = append(candidates, w)
			}
		}
	}

	var completions [][]rune
	for _, name := range candidates {
		if strings.HasPrefix(name, prefix) {
			completions = append(completions, []rune(name[len(prefix):]))
		}
	}
	return completions, len(prefix)
}

// completeFile returns suffix completions for a partial file path.
func (c *adsshCompleter) completeFile(prefix string) ([][]rune, int) {
	var dir, base string

	if prefix == "" || strings.HasSuffix(prefix, "/") {
		dir = prefix
		if dir == "" {
			dir = "."
		}
		base = ""
	} else {
		dir = filepath.Dir(prefix)
		base = filepath.Base(prefix)
	}

	// Expand leading ~
	expandedDir := dir
	if strings.HasPrefix(dir, "~") {
		if homeDir, err := os.UserHomeDir(); err == nil {
			expandedDir = homeDir + dir[1:]
		}
	}

	entries, err := os.ReadDir(expandedDir)
	if err != nil {
		return nil, 0
	}

	var completions [][]rune
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, base) {
			continue
		}
		suffix := name[len(base):]
		if entry.IsDir() {
			suffix += "/"
		}
		completions = append(completions, []rune(suffix))
	}
	return completions, len(base)
}
