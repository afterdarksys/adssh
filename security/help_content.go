package security

// help_content.go — static help entries for builtins, security concepts,
// Starlark namespaces, and shell concepts.

func init() {
	registerBuiltinHelp()
	registerSecurityHelp()
	registerStarlarkHelp()
	registerConceptHelp()
}

// ── Shell builtins ────────────────────────────────────────────────────────────

func registerBuiltinHelp() {
	builtins := []HelpEntry{
		{
			Name:        "alias",
			Category:    "builtin",
			Summary:     "Define or display command aliases",
			Description: "Creates a shorthand name for a command or series of commands. Without arguments, lists all defined aliases.",
			Usage:       "alias [name[=value] ...]",
			Examples: []HelpExample{
				{Command: "alias ll='ls -la'", Description: "create alias ll"},
				{Command: "alias", Description: "list all aliases"},
			},
			SeeAlso: []string{"unalias"},
			Tags:    []string{"alias", "shorthand", "abbreviation"},
		},
		{
			Name:        "unalias",
			Category:    "builtin",
			Summary:     "Remove one or more aliases",
			Description: "Removes the named alias definitions. Use -a to remove all aliases.",
			Usage:       "unalias [-a] name [name ...]",
			Examples: []HelpExample{
				{Command: "unalias ll", Description: "remove the ll alias"},
				{Command: "unalias -a", Description: "remove all aliases"},
			},
			SeeAlso: []string{"alias"},
			Tags:    []string{"alias", "remove"},
		},
		{
			Name:        "set",
			Category:    "builtin",
			Summary:     "Set or unset shell options and positional parameters",
			Description: "Controls shell behavior flags. Common flags: -e (exit on error), -u (error on unset variables), -x (trace commands), -o pipefail (fail on pipe errors).",
			Usage:       "set [-e | +e | -u | +u | -x | +x | -o option | +o option]",
			Examples: []HelpExample{
				{Command: "set -e", Description: "exit immediately on error"},
				{Command: "set -x", Description: "enable command tracing"},
				{Command: "set +x", Description: "disable command tracing"},
				{Command: "set -o pipefail", Description: "fail if any pipe command fails"},
			},
			Tags: []string{"options", "flags", "errexit", "nounset", "xtrace"},
		},
		{
			Name:        "source",
			Category:    "builtin",
			Summary:     "Execute commands from a file in the current shell",
			Description: "Reads and executes commands from the given file in the current shell environment. Changes to variables and functions persist after source returns.",
			Usage:       "source <file> [args ...]\n. <file> [args ...]",
			Examples: []HelpExample{
				{Command: "source ~/.adsshrc", Description: "reload shell configuration"},
				{Command: ". ./env.sh", Description: "load environment variables"},
			},
			Tags: []string{"source", "dot", "include", "import", "load"},
		},
		{
			Name:        "pushd",
			Category:    "builtin",
			Summary:     "Push a directory onto the directory stack",
			Description: "Saves the current directory and changes to the specified directory. Use popd to return. dirs shows the current stack.",
			Usage:       "pushd [dir]",
			Examples: []HelpExample{
				{Command: "pushd /tmp", Description: "switch to /tmp, saving current dir"},
				{Command: "pushd", Description: "swap top two directories on stack"},
			},
			SeeAlso: []string{"popd", "dirs"},
			Tags:    []string{"directory", "stack", "pushd", "navigation"},
		},
		{
			Name:        "popd",
			Category:    "builtin",
			Summary:     "Pop a directory from the directory stack",
			Description: "Removes the top entry from the directory stack and changes to the new top directory.",
			Usage:       "popd",
			Examples: []HelpExample{
				{Command: "popd", Description: "return to previously pushed directory"},
			},
			SeeAlso: []string{"pushd", "dirs"},
			Tags:    []string{"directory", "stack", "navigation"},
		},
		{
			Name:        "dirs",
			Category:    "builtin",
			Summary:     "Display the directory stack",
			Description: "Prints the list of currently remembered directories, most recently pushed first.",
			Usage:       "dirs [-c | -l | -p | -v]",
			Examples: []HelpExample{
				{Command: "dirs", Description: "show directory stack"},
				{Command: "dirs -v", Description: "show stack with indices"},
			},
			SeeAlso: []string{"pushd", "popd"},
			Tags:    []string{"directory", "stack"},
		},
		{
			Name:        "trap",
			Category:    "builtin",
			Summary:     "Execute a command when the shell receives a signal",
			Description: "Registers a command to be executed when the shell receives the specified signal. Common signals: EXIT, INT, TERM, ERR.",
			Usage:       "trap [command] [signal ...]",
			Examples: []HelpExample{
				{Command: "trap 'echo Bye' EXIT", Description: "run on shell exit"},
				{Command: "trap '' INT", Description: "ignore Ctrl-C"},
				{Command: "trap - INT", Description: "reset INT to default"},
			},
			Tags: []string{"trap", "signal", "interrupt", "EXIT", "cleanup"},
		},
		{
			Name:        "read",
			Category:    "builtin",
			Summary:     "Read a line from stdin into a variable",
			Description: "Reads one line from standard input (or a file descriptor) and assigns it to the named variable(s).",
			Usage:       "read [-r] [-p prompt] [-s] [var ...]",
			Examples: []HelpExample{
				{Command: "read name", Description: "read a line into $name"},
				{Command: "read -p 'Enter value: ' val", Description: "show prompt and read"},
				{Command: "read -s password", Description: "read without echoing (for passwords)"},
			},
			Tags: []string{"read", "input", "stdin", "prompt"},
		},
		{
			Name:        "type",
			Category:    "builtin",
			Summary:     "Describe how the shell will interpret a name",
			Description: "Indicates whether a name is a shell builtin, alias, function, virtual binary, or external command.",
			Usage:       "type [-a] name [name ...]",
			Examples: []HelpExample{
				{Command: "type ls", Description: "show what ls resolves to"},
				{Command: "type -a python", Description: "show all matches for python"},
			},
			Tags: []string{"type", "which", "command", "builtin"},
		},
		{
			Name:        "time",
			Category:    "builtin",
			Summary:     "Time the execution of a command",
			Description: "Reports the real, user, and system time consumed by a pipeline.",
			Usage:       "time [pipeline]",
			Examples: []HelpExample{
				{Command: "time ls -R /", Description: "time a recursive directory listing"},
			},
			Tags: []string{"time", "benchmark", "performance"},
		},
		{
			Name:        "cd",
			Category:    "builtin",
			Summary:     "Change the current working directory",
			Description: "Changes the shell's working directory. With no arguments, changes to $HOME. Use - to switch to the previous directory.",
			Usage:       "cd [dir]",
			Examples: []HelpExample{
				{Command: "cd /tmp", Description: "change to /tmp"},
				{Command: "cd -", Description: "return to previous directory"},
				{Command: "cd", Description: "go to home directory"},
			},
			Tags: []string{"cd", "directory", "navigate"},
		},
		{
			Name:        "export",
			Category:    "builtin",
			Summary:     "Set environment variables for child processes",
			Description: "Marks variables for export to the environment of subsequently executed commands.",
			Usage:       "export [name[=value] ...]",
			Examples: []HelpExample{
				{Command: "export PATH=$PATH:/usr/local/bin", Description: "extend PATH"},
				{Command: "export DEBUG=1", Description: "set a debug flag"},
			},
			Tags: []string{"export", "environment", "variable", "env"},
		},
		{
			Name:        "exit",
			Category:    "builtin",
			Summary:     "Exit the shell with a given status",
			Description: "Causes the shell to exit with the specified numeric status code (default 0). Any EXIT traps are executed before the shell exits.",
			Usage:       "exit [n]",
			Examples: []HelpExample{
				{Command: "exit", Description: "exit with status 0"},
				{Command: "exit 1", Description: "exit with status 1 (error)"},
			},
			Tags: []string{"exit", "quit", "bye"},
		},
	}

	for _, e := range builtins {
		RegisterHelp(e)
	}
}

// ── Security concepts ─────────────────────────────────────────────────────────

func registerSecurityHelp() {
	entries := []HelpEntry{
		{
			Name:     "policy",
			Category: "security",
			Summary:  "Rego/OPA policy engine — allow or deny commands based on rules",
			Description: `adssh embeds an OPA (Open Policy Agent) engine. Policies are written in Rego
and evaluated before every command execution.

A policy file defines an allow or deny decision. If no policy is loaded all
commands are allowed.

The policy context includes: user, command, args, hostname, session_id,
principals (roles), and environment variables.

The policy file is loaded at startup from ADSSH_POLICY or --policy
(default ~/.adssh/policy.rego). Decisions are recorded in the audit log.`,
			Usage: "ADSSH_POLICY=/path/to/policy.rego adssh\nadssh --policy /path/to/policy.rego",
			Examples: []HelpExample{
				{Command: `package adssh.authz
default allow = false
allow { input.command != "rm" }`, Description: "deny the rm command"},
				{Command: `allow { input.principals[_] == "admin" }`, Description: "allow admins only"},
			},
			SeeAlso: []string{"audit", "rbac", "4eyes"},
			Tags:    []string{"policy", "rego", "opa", "allow", "deny", "rules"},
		},
		{
			Name:     "restricted",
			Category: "security",
			Summary:  "Restricted shell mode — limits command execution",
			Description: `Restricted mode refuses these operations:
  • cd (any directory)
  • export
  • commands with / in the name, such as /bin/echo or ./run.sh
  • redirection to /dev/tcp and /dev/udp
  • Starlark file, network and exec builtins, which are left out of the
    session: sys.read_file, sys.write_file, sys.exec_cmd, sys.exec_async,
    sys.exec_json, sys.parallel, sys.register_command, sys.load_plugin,
    sys.load_plugins, and every net function
  • plugin loads and governed fs writes

Restricted mode does NOT block file redirection (echo hi > file works) or
assignments such as PATH=/somewhere. Use the Rego policy for those.

Enable restricted mode with the -r flag or ADSSH_RESTRICTED=1.
Check the current mode with sec.is_restricted() in Starlark.`,
			Usage:   "adssh -r\nADSSH_RESTRICTED=1 adssh",
			SeeAlso: []string{"policy", "audit"},
			Tags:    []string{"restricted", "security", "sandbox", "rbac"},
		},
		{
			Name:     "audit",
			Category: "security",
			Summary:  "Audit logging and tamper-evident chain integrity",
			Description: `Every command executed in adssh is recorded in an append-only audit log.
The log uses a cryptographic hash chain so that any tampering is detectable.

Log location: ~/.adssh/audit.log (override with ADSSH_AUDIT_LOG).
Chain file:   the log path plus .chain, e.g. ~/.adssh/audit.log.chain

Remote SIEM forwarding is configured via ADSSH_AUDIT_URL and
ADSSH_AUDIT_TOKEN environment variables.

Syslog forwarding is enabled via ADSSH_SYSLOG=auth|daemon|local0..7.

Each chain entry contains: type, source, command, user, timestamp, prev_hash, hash.`,
			Usage: "ADSSH_AUDIT_LOG=/var/log/adssh.log adssh\nADSSH_AUDIT_URL=https://siem/ ADSSH_AUDIT_TOKEN=xxx adssh",
			Examples: []HelpExample{
				{Command: "audit tail -n 20", Description: "show the last 20 audit entries"},
				{Command: "audit verify", Description: "verify chain integrity"},
				{Command: "sec.audit('custom event')", Description: "write audit entry from Starlark"},
			},
			SeeAlso: []string{"policy", "4eyes", "cm"},
			Tags:    []string{"audit", "log", "chain", "siem", "compliance", "integrity"},
		},
		{
			Name:     "4eyes",
			Category: "security",
			Summary:  "Dual-approval gate for sensitive commands",
			Description: `4eyes requires a second authorized user to approve commands matching registered
patterns before they execute. Required for SOX, PCI-DSS, and FedRAMP compliance.

When a command matches a 4eyes rule, the shell prints a token and pauses.
The approver runs '4eyes approve <token>' on their own session.
If approved the command proceeds; if denied or timed out it is canceled.

Webhook notifications: set ADSSH_4EYES_WEBHOOK=<url> to POST approval
requests to a Slack/Teams/PagerDuty webhook.`,
			Usage: `4eyes add <pattern> [--approver user] [--ttl seconds]
4eyes approve <token>
4eyes deny <token>
4eyes list
4eyes pending
4eyes remove <pattern>`,
			Examples: []HelpExample{
				{Command: `4eyes add "drop *"`, Description: "require approval for all drop commands"},
				{Command: `4eyes add "kubectl delete *" --approver ops@corp.com`, Description: "named approver"},
				{Command: "4eyes list", Description: "show rules and pending approvals"},
				{Command: "4eyes approve abc123", Description: "approve a pending request"},
				{Command: "4eyes deny abc123", Description: "deny a pending request"},
			},
			SeeAlso: []string{"cm", "audit", "policy"},
			Tags:    []string{"4eyes", "foureyes", "dual", "approval", "sox", "pci", "compliance"},
		},
		{
			Name:     "cm",
			Category: "security",
			Summary:  "Change management — require a ticket before executing changes",
			Description: `The cm (change management) integration requires operators to associate a
change ticket with their session before running commands that match CM rules.

Once a ticket is set, every audit log entry includes the ticket ID so that
changes can be traced back to approved work orders.

Integrations: ServiceNow, Jira, GitHub Issues (via Starlark plugins).`,
			Usage: `cm set <ticket-id>
cm status
cm clear`,
			Examples: []HelpExample{
				{Command: "cm set CHG0012345", Description: "associate ticket with session"},
				{Command: "cm status", Description: "show the active ticket"},
				{Command: "cm clear", Description: "remove ticket association"},
			},
			SeeAlso: []string{"4eyes", "audit", "policy"},
			Tags:    []string{"cm", "change", "ticket", "itil", "servicenow", "jira", "compliance"},
		},
		{
			Name:     "rbac",
			Category: "security",
			Summary:  "Role-based access control and entitlements file format",
			Description: `adssh RBAC is driven by an entitlements YAML file that maps principals
(users / groups) to the commands and resources they may access.

Entitlements file format (YAML):
  principals:
    - name: alice
      roles: [developer, deployer]
    - name: ops-team
      roles: [operator, admin]

  roles:
    developer:
      allow: ["git *", "kubectl get *", "kubectl describe *"]
      deny:  ["kubectl delete *", "kubectl exec *"]
    deployer:
      allow: ["kubectl apply *", "helm *"]
    operator:
      allow: ["*"]
      deny:  ["rm -rf *"]

Load: ADSSH_ENTITLEMENTS=/path/to/ent.yaml
Runtime: sec.check_policy(command) in Starlark
Temporary escalation: grant request <role>`,
			Usage:   "ADSSH_ENTITLEMENTS=/path/entitlements.yaml adssh",
			SeeAlso: []string{"policy", "grant", "4eyes"},
			Tags:    []string{"rbac", "roles", "entitlements", "principals", "access", "permissions"},
		},
	}

	for _, e := range entries {
		RegisterHelp(e)
	}
}

// ── Starlark namespaces ───────────────────────────────────────────────────────

func registerStarlarkHelp() {
	entries := []HelpEntry{
		{
			Name:     "sys",
			Category: "starlark",
			Summary:  "System operations — env vars, files, processes, plugins",
			Description: `The sys namespace provides system-level operations: environment variables,
file I/O, process execution, plugin loading, and terminal control.

exec_cmd, exec_json and exec_async take ONE string, not a list. The string is
run by the adssh shell, so every command in it passes the same policy check as
a typed command. exec_cmd returns standard output and standard error together
as one string. A command that exits non-zero raises an error with the exit
status and the last 4 KiB of the output, which stops the Starlark code.
exec_json parses whole numbers as ints. timeout= is in seconds (default 30).`,
			Usage: "sys.<method>(args...)",
			Examples: []HelpExample{
				{Command: "sys.getenv('HOME')", Description: "read HOME env var"},
				{Command: "sys.setenv('DEBUG', '1')", Description: "set env var"},
				{Command: "sys.read_file('/etc/hostname')", Description: "read file contents"},
				{Command: "sys.write_file('/tmp/out.txt', 'hello')", Description: "write file"},
				{Command: `sys.exec_cmd("ls -la")`, Description: "run one command string, return stdout and stderr"},
				{Command: `sys.exec_cmd("make test", timeout=300)`, Description: "raise the 30 second default timeout"},
				{Command: `j = sys.exec_async("sleep 5; echo done")`, Description: "start a job; j.wait(), j.output()"},
				{Command: `sys.exec_json("cat file.json")`, Description: "run a command, parse its output as JSON"},
				{Command: `sys.parallel(["echo a", "echo b"], jobs=2)`, Description: "run gated command strings together"},
				{Command: "sys.load_plugin('/path/to/plugin.so')", Description: "load a plugin"},
				{Command: `sys.load_plugins(names=["hello"])`, Description: "load checked Starlark plugins"},
				{Command: "sys.register_command('myfn', handler)", Description: "register custom command"},
			},
			SeeAlso: []string{"plugins", "hooks"},
			Tags:    []string{"sys", "system", "env", "file", "exec", "process", "plugin"},
		},
		{
			Name:        "net",
			Category:    "starlark",
			Summary:     "Network — HTTP requests and TCP connections",
			Description: "The net namespace provides HTTP GET, TCP send, and TCP, TLS and UDP dial operations. It is empty in restricted mode.",
			Usage:       "net.<method>(args...)",
			Examples: []HelpExample{
				{Command: "net.http_get('https://api.example.com/status')", Description: "HTTP GET"},
				{Command: "net.tcp_send('localhost:9000', 'PING')", Description: "raw TCP send"},
				{Command: "net.dial('tcp', 'localhost:22')", Description: "dial a TCP connection"},
				{Command: "net.dial_tls('example.com:443')", Description: "dial with TLS (certificate verified)"},
			},
			Tags: []string{"net", "network", "http", "tcp", "tls", "request"},
		},
		{
			Name:        "crypto",
			Category:    "starlark",
			Summary:     "Cryptographic hashing — MD5, SHA-256",
			Description: "The crypto namespace provides hashing functions.",
			Usage:       "crypto.<method>(data)",
			Examples: []HelpExample{
				{Command: "crypto.md5('hello')", Description: "compute MD5 hex digest"},
				{Command: "crypto.sha256('hello')", Description: "compute SHA-256 hex digest"},
			},
			Tags: []string{"crypto", "hash", "md5", "sha256", "checksum"},
		},
		{
			Name:        "data",
			Category:    "starlark",
			Summary:     "Data serialization — JSON and YAML parse",
			Description: "The data namespace parses JSON and YAML strings into Starlark values. Whole JSON numbers parse as ints, the rest as floats. json_dump and yaml_dump encode a dict (string keys), list, tuple, str, int, float, bool or None with sorted keys; any other value is an error. Parsed dicts use index access, d[\"key\"], not d.key.",
			Usage:       "data.<method>(value)",
			Examples: []HelpExample{
				{Command: `data.json_parse('{"key":"value"}')`, Description: "parse JSON string"},
				{Command: "data.json_dump({'key': 'value'})", Description: "encode as compact JSON with sorted keys"},
				{Command: "data.yaml_parse('key: value')", Description: "parse YAML string"},
				{Command: "data.yaml_dump({'key': 'value'})", Description: "encode as YAML with sorted keys"},
			},
			// nolint:misspell // "serialise" kept intentionally alongside "serialize" so
			// help search matches either British or American spelling.
			Tags: []string{"data", "json", "yaml", "parse", "serialise", "serialize"},
		},
		{
			Name:        "re",
			Category:    "starlark",
			Summary:     "Regular expressions — Go regexp and PCRE matching",
			Description: "The re namespace provides regex match functions using Go's regexp syntax and PCRE.",
			Usage:       "re.<method>(pattern, string)",
			Examples: []HelpExample{
				{Command: `re.match(r"^v\d+\.\d+", "v1.2.3")`, Description: "match with Go regexp"},
				{Command: `re.pcre_match(r"(?i)hello", "HELLO")`, Description: "case-insensitive PCRE match"},
			},
			Tags: []string{"re", "regex", "regexp", "pcre", "pattern", "match"},
		},
		{
			Name:        "sec",
			Category:    "starlark",
			Summary:     "Security primitives — audit, restriction checks, file hashing, policy",
			Description: "The sec namespace exposes security primitives for Starlark scripts.",
			Usage:       "sec.<method>(args...)",
			Examples: []HelpExample{
				{Command: `sec.audit("deployed v1.2")`, Description: "write an audit log entry"},
				{Command: "sec.is_restricted()", Description: "check if shell is in restricted mode"},
				{Command: `sec.file_hash("/etc/passwd")`, Description: "compute SHA-256 of a file"},
				{Command: `sec.check_policy("rm -rf /")`, Description: "evaluate policy for a command"},
			},
			SeeAlso: []string{"audit", "policy", "restricted"},
			Tags:    []string{"sec", "security", "audit", "policy", "hash", "restricted"},
		},
		{
			Name:     "aws",
			Category: "starlark",
			Summary:  "Amazon Web Services — EC2, S3, ECS, Lambda",
			Description: `The aws namespace provides sub-namespaces for AWS services.
Credentials are read from the standard AWS credential chain (env vars, ~/.aws/credentials, IAM role).`,
			Usage: "aws.<service>.<method>(args...)",
			Examples: []HelpExample{
				{Command: "aws.ec2.list_instances()", Description: "list EC2 instances"},
				{Command: `aws.ec2.start_instance("i-1234567890abcdef0")`, Description: "start an instance"},
				{Command: `aws.ec2.stop_instance("i-1234567890abcdef0")`, Description: "stop an instance"},
				{Command: `aws.ec2.terminate_instance("i-1234567890abcdef0")`, Description: "terminate an instance"},
				{Command: "aws.s3.list_buckets()", Description: "list S3 buckets"},
				{Command: `aws.s3.get_object("my-bucket", "key.txt")`, Description: "get S3 object"},
				{Command: `aws.s3.put_object("my-bucket", "key.txt", "data")`, Description: "put S3 object"},
				{Command: `aws.s3.delete_object("my-bucket", "key.txt")`, Description: "delete S3 object"},
				{Command: "aws.ecs.list_clusters()", Description: "list ECS clusters"},
				{Command: `aws.ecs.list_services("cluster-arn")`, Description: "list ECS services"},
				{Command: "aws.lambda.list_functions()", Description: "list Lambda functions"},
				{Command: `aws.lambda.invoke("my-function", {"key": "val"})`, Description: "invoke Lambda"},
				{Command: "aws.cloudwatch.list_alarms()", Description: "list CloudWatch alarms"},
				{Command: `aws.route53.list_zones()`, Description: "list Route53 hosted zones"},
			},
			Tags: []string{"aws", "ec2", "s3", "ecs", "lambda", "cloud", "amazon", "list_instances", "start_instance", "stop_instance", "terminate_instance"},
		},
		{
			Name:     "gcp",
			Category: "starlark",
			Summary:  "Google Cloud Platform — Compute, Storage, GKE, Pub/Sub, Cloud Run",
			Description: `The gcp namespace provides sub-namespaces for GCP services.
Credentials are read from GOOGLE_APPLICATION_CREDENTIALS or Application Default Credentials.`,
			Usage: "gcp.<service>.<method>(args...)",
			Examples: []HelpExample{
				{Command: `gcp.compute.list_instances("my-project", "us-central1-a")`, Description: "list Compute instances"},
				{Command: `gcp.compute.start_instance("project", "zone", "instance")`, Description: "start instance"},
				{Command: `gcp.compute.stop_instance("project", "zone", "instance")`, Description: "stop instance"},
				{Command: `gcp.storage.list_buckets("my-project")`, Description: "list GCS buckets"},
				{Command: `gcp.gke.list_clusters("my-project", "us-central1")`, Description: "list GKE clusters"},
				{Command: `gcp.pubsub.list_topics("my-project")`, Description: "list Pub/Sub topics"},
				{Command: `gcp.run.list_services("my-project", "us-central1")`, Description: "list Cloud Run services"},
			},
			Tags: []string{"gcp", "gke", "compute", "storage", "pubsub", "cloud run", "google", "cloud"},
		},
		{
			Name:        "oci",
			Category:    "starlark",
			Summary:     "Oracle Cloud Infrastructure — Compute and Object Storage",
			Description: "The oci namespace provides access to OCI Compute instances and Object Storage.",
			Usage:       "oci.<service>.<method>(args...)",
			Examples: []HelpExample{
				{Command: `oci.compute.list_instances("compartment-ocid")`, Description: "list OCI instances"},
				{Command: `oci.compute.start_instance("instance-ocid")`, Description: "start OCI instance"},
				{Command: `oci.storage.list_buckets("namespace", "compartment-ocid")`, Description: "list buckets"},
			},
			Tags: []string{"oci", "oracle", "cloud", "compute", "storage"},
		},
		{
			Name:        "git",
			Category:    "starlark",
			Summary:     "Git operations — clone, status, commit, push, pull",
			Description: "The git namespace wraps go-git to provide repository operations from Starlark.",
			Usage:       "git.<method>(args...)",
			Examples: []HelpExample{
				{Command: `git.clone("https://github.com/org/repo", "/tmp/repo")`, Description: "clone a repo"},
				{Command: `r = git.open("/tmp/repo"); git.status(r)`, Description: "open and check status"},
				{Command: `git.add(r, ["file.go"])`, Description: "stage files"},
				{Command: `git.commit(r, "Fix bug", "Author <a@b.com>")`, Description: "commit"},
				{Command: `git.push(r, "origin", "main")`, Description: "push to remote"},
				{Command: `git.log(r, 10)`, Description: "show last 10 commits"},
			},
			Tags: []string{"git", "vcs", "version control", "clone", "commit", "push", "pull"},
		},
		{
			Name:        "github",
			Category:    "starlark",
			Summary:     "GitHub API — repos, PRs, issues, releases, workflows",
			Description: "The github namespace provides GitHub API operations. Set GITHUB_TOKEN for authentication.",
			Usage:       "github.<method>(args...)",
			Examples: []HelpExample{
				{Command: `github.list_repos("org")`, Description: "list org repos"},
				{Command: `github.list_prs("org/repo")`, Description: "list pull requests"},
				{Command: `github.create_pr("org/repo", "title", "body", "feature", "main")`, Description: "create PR"},
				{Command: `github.list_issues("org/repo")`, Description: "list issues"},
				{Command: `github.create_issue("org/repo", "title", "body")`, Description: "create issue"},
				{Command: `github.trigger_workflow("org/repo", "deploy.yml", "main", {})`, Description: "trigger workflow"},
			},
			Tags: []string{"github", "git", "pr", "pull request", "issue", "workflow", "release"},
		},
		{
			Name:        "k8s",
			Category:    "starlark",
			Summary:     "Kubernetes — pods, deployments, services, namespaces, events",
			Description: "The k8s namespace provides Kubernetes cluster operations via the in-cluster or kubeconfig credentials.",
			Usage:       "k8s.<resource>(...)",
			Examples: []HelpExample{
				{Command: "k8s.pods()", Description: "list pods in default namespace"},
				{Command: `k8s.pods(namespace="kube-system")`, Description: "list pods in kube-system"},
				{Command: "k8s.deployments()", Description: "list deployments"},
				{Command: "k8s.services()", Description: "list services"},
				{Command: "k8s.namespaces()", Description: "list namespaces"},
				{Command: "k8s.nodes()", Description: "list nodes"},
				{Command: "k8s.events()", Description: "list recent events"},
				{Command: "k8s.configmaps()", Description: "list config maps"},
			},
			SeeAlso: []string{"docker", "containers"},
			Tags:    []string{"k8s", "kubernetes", "pods", "deployments", "services", "kubectl", "helm"},
		},
		{
			Name:        "docker",
			Category:    "starlark",
			Summary:     "Docker Engine API — containers, images, networks, volumes",
			Description: "The docker namespace wraps the Docker Engine API for container management.",
			Usage:       "docker.<method>(args...)",
			Examples: []HelpExample{
				{Command: "docker.ps()", Description: "list running containers"},
				{Command: `docker.inspect("container-id")`, Description: "inspect a container"},
				{Command: `docker.logs("container-id")`, Description: "fetch container logs"},
				{Command: "docker.images()", Description: "list images"},
				{Command: "docker.networks()", Description: "list networks"},
				{Command: "docker.volumes()", Description: "list volumes"},
			},
			SeeAlso: []string{"containers", "k8s"},
			Tags:    []string{"docker", "container", "image", "network", "volume"},
		},
		{
			Name:     "containers",
			Category: "starlark",
			Summary:  "Audited container execution — exec, list, audit trail",
			Description: `The containers namespace provides audited container execution with a
tamper-evident audit trail. Every container execution is recorded.`,
			Usage: "containers.<method>(args...)",
			Examples: []HelpExample{
				{Command: `containers.exec("ubuntu:22.04", ["bash", "-c", "id"])`, Description: "run command in container"},
				{Command: "containers.list()", Description: "list recent container sessions"},
				{Command: "containers.audit()", Description: "view audit records"},
				{Command: `containers.replay("session-id")`, Description: "replay container session"},
				{Command: "containers.clean()", Description: "clean up old sessions"},
			},
			SeeAlso: []string{"docker", "k8s", "audit"},
			Tags:    []string{"containers", "exec", "docker", "audit", "replay"},
		},
		{
			Name:        "secrets",
			Category:    "starlark",
			Summary:     "Secrets management — Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager",
			Description: "The secrets namespace provides a unified interface to multiple secrets backends.",
			Usage:       "secrets.<backend>.<method>(args...)",
			Examples: []HelpExample{
				{Command: `secrets.vault.get("secret/myapp/db_password")`, Description: "read from Vault"},
				{Command: `secrets.aws.get("prod/myapp/api_key")`, Description: "read from AWS Secrets Manager"},
				{Command: `secrets.az.get("my-keyvault", "db-password")`, Description: "read from Azure Key Vault"},
				{Command: `secrets.gcp.get("my-project", "db-password")`, Description: "read from GCP Secret Manager"},
			},
			Tags: []string{"secrets", "vault", "aws", "azure", "gcp", "credentials", "password"},
		},
		{
			Name:        "db",
			Category:    "starlark",
			Summary:     "Database clients — PostgreSQL, MySQL, Redis",
			Description: "The db namespace provides database connection helpers.",
			Usage:       "db.<engine>.<method>(args...)",
			Examples: []HelpExample{
				{Command: `db.postgres.query("postgres://user:pw@host/db", "SELECT 1")`, Description: "Postgres query"},
				{Command: `db.mysql.query("user:pw@tcp(host:3306)/db", "SELECT 1")`, Description: "MySQL query"},
				{Command: `db.redis.get("redis://localhost:6379", "mykey")`, Description: "Redis get"},
			},
			Tags: []string{"db", "database", "postgres", "mysql", "redis", "sql", "query"},
		},
		{
			Name:        "notify",
			Category:    "starlark",
			Summary:     "Notifications — Slack, webhook, PagerDuty, Teams",
			Description: "The notify namespace sends notifications to various channels.",
			Usage:       "notify.<channel>.<method>(args...)",
			Examples: []HelpExample{
				{Command: `notify.slack.send("https://hooks.slack.com/...", "Deploy complete")`, Description: "Slack notification"},
				{Command: `notify.webhook.post("https://...", {"text": "alert"})`, Description: "generic webhook"},
				{Command: `notify.pagerduty.trigger("routing-key", "incident title")`, Description: "PagerDuty alert"},
				{Command: `notify.teams("", "Deploy", "Deploy complete")`, Description: "Teams notification"},
			},
			Tags: []string{"notify", "slack", "pagerduty", "teams", "webhook", "alert", "notification"},
		},
		{
			Name:        "template",
			Category:    "starlark",
			Summary:     "Go text/template rendering",
			Description: "The template namespace renders Go text/template strings and files.",
			Usage:       "template.<method>(args...)",
			Examples: []HelpExample{
				{Command: `template.render("Hello {{.Name}}!", {"Name": "World"})`, Description: "render a template string"},
				{Command: `template.render_file("/etc/nginx/nginx.conf.tmpl", vars)`, Description: "render a template file"},
			},
			Tags: []string{"template", "render", "golang", "text/template"},
		},
	}

	for _, e := range entries {
		RegisterHelp(e)
	}
}

// ── Concepts ──────────────────────────────────────────────────────────────────

func registerConceptHelp() {
	entries := []HelpEntry{
		{
			Name:     "starlark",
			Category: "concept",
			Summary:  "Starlark primer — variables, blocks, data, namespaces, errors",
			Description: `Starlark is a small dialect of Python. At the adssh prompt a line runs as
Starlark when it is an assignment (x = 5), starts with def, for, print( or
"if ...:", or starts with a known name (a variable, a namespace such as sys,
or a builtin such as len) and reads as an expression. Everything else is a
shell command. Start a line with ! to force the shell. help adssh-starlark
has the exact rules.

VARIABLES
Variables last for the whole session: set x = 5 on one line and use x on the
next. Assigning again replaces the value. A line that starts with a number,
such as 1 + 2, goes to the shell; type print(1 + 2) instead.

BLOCKS
A line that ends in a colon (def, for, if) opens a block. The prompt changes
to "...   " and you type the body indented by four spaces. An empty line ends
the block and runs it. Ctrl-C at the "..." prompt also ends the block, and
what you typed so far still runs.

DATA
Lists: [1, 2, 3]. Dicts: {"name": "web", "port": 80}. Sets: set([1, 2]).
Comprehensions: [n * n for n in range(5)]. Index with xs[0] and d["name"].
Format with "%s has %d items" % (name, len(xs)).

NAMESPACES
adssh adds namespaces such as sys, str, data, fs, re, crypto and net. Call a
function with a dot: sys.getenv("HOME"). Each namespace has its own help
topic, for example help sys. str is a namespace in adssh (str.upper("a")),
and calling it is still the str() builtin: str(5) is "5".

RUNNING COMMANDS
sys.exec_cmd("uname -a") runs one command string through the adssh shell
and returns its standard output and standard error together as a string.
Assign the result to keep it: out = sys.exec_cmd("uname -a"). It takes one
string, not a list. A command that exits non-zero raises an error that ends
with the command's output.

ERRORS
An error prints "starlark error:" and the message, and stops that line or
block. Starlark has no try or except, so check values before you use them.
fail("message") raises an error of your own.

STOPPING
Ctrl-C stops a Starlark line that is running.`,
			Examples: []HelpExample{
				{Command: `x = 5`, Description: "set a variable"},
				{Command: `print(x * 2)`, Description: "use it on a later line"},
				{Command: `names = ["web", "db"]`, Description: "a list"},
				{Command: `for n in names:`, Description: "opens a block; the prompt becomes ..."},
				{Command: `    print(n)`, Description: "the indented body"},
				{Command: `(empty line)`, Description: "ends the block and runs it"},
				{Command: `def double(n):`, Description: "define a function"},
				{Command: `    return n * 2`, Description: "its body; then an empty line"},
				{Command: `print(double(21))`, Description: "call it"},
				{Command: `out = sys.exec_cmd("uname -a")`, Description: "capture a command's output"},
				{Command: `cfg = data.json_parse('{"port": 80}')`, Description: "parse JSON"},
				{Command: `print(cfg["port"])`, Description: "index a dict"},
			},
			SeeAlso: []string{"adssh-starlark", "sys", "data", "start", "hooks"},
			Tags:    []string{"starlark", "scripting", "language", "python", "mode", "eval", "primer", "variables", "def", "for"},
		},
		{
			Name:     "adssh-starlark",
			Category: "concept",
			Summary:  "What adssh adds to stock Starlark: options, namespaces, policy, routing",
			Description: `LANGUAGE OPTIONS
adssh turns on three go.starlark.net options. AllowSet adds the set()
builtin. AllowGlobalReassign lets a top-level name be assigned again and
allows while loops and if, for and while at the top level. AllowRecursion
lets a function call itself.

NAMESPACES
sys str data fs re crypto net log sec template cloud aws gcp az oci k8s
secrets db notify git github docker containers i18n expect.
A namespace is read-only. Reach a member with a dot, sys.getenv, or with an
index, sys["getenv"]. Dicts that functions return are ordinary dicts: use
d["key"], not d.key. In restricted mode the file, network and exec members
are missing (help restricted).

GOVERNANCE
Every namespace function call is checked by the Rego policy, as the command
starlark.<namespace>.<function> (for example starlark.sys.exec_cmd) with
its arguments, and audited before it runs. A command string given to
sys.exec_cmd, sys.exec_json, sys.exec_async or sys.parallel is then run by
the adssh shell, and each command inside it is checked again.

ROUTING
The first rule that matches decides:
1. A line starting with ! or "$ " goes to the shell.
2. "if ...:" is Starlark; a POSIX "if ...; then" is shell.
3. A line starting with def, for or print( is Starlark.
4. A line starting with [ or export, or of the form NAME=value command, is shell.
5. A line with = that parses as a Starlark assignment is Starlark, so x = 5 is
Starlark and ls --color=auto is shell.
6. A line whose first word is a Starlark name and which parses as an
expression is Starlark, unless it is also valid shell and that word is an
alias, a registered command, a vbin, a shell builtin or a program on PATH.
7. Everything else is shell.

NOT SUPPORTED
load() is not available. A line starting with load( runs as Starlark and
fails with "load not implemented by this application".
sys.exec_cmd, sys.exec_json and sys.exec_async take one string, not a list.
Starlark has no set literal: s = {1, 2} fails with a Starlark syntax error
that names the fix. Write s = set([1, 2]).

EXTRAS
sys.exec_async("cmd") returns a job: j.wait() returns True or an error
string, j.output() waits and returns standard output, and j.stop(),
j.resume() and j.kill() control it. sys.parallel(["cmd a", "cmd b"],
jobs=2) runs command strings together and returns a list of outputs.
sys.register_command(name, fn) adds a shell command; fn receives the argv
list. __preexec__ and __postcmd__ hooks can be set only in a profile
(help hooks).`,
			Examples: []HelpExample{
				{Command: `s = set([1, 2])`, Description: "AllowSet"},
				{Command: `print(sys["getenv"]("HOME"))`, Description: "index access to a namespace"},
				{Command: `j = sys.exec_async("sleep 2; echo done")`, Description: "start a job"},
				{Command: `print(j.output())`, Description: "wait for it and print its output"},
				{Command: `print(sys.parallel(["echo a", "echo b"], jobs=2))`, Description: "run two commands together"},
				{Command: `! ls`, Description: "force the shell"},
			},
			SeeAlso: []string{"starlark", "sys", "policy", "restricted", "hooks"},
			Tags:    []string{"starlark", "adssh", "routing", "namespaces", "governance", "load", "AllowSet", "AllowRecursion", "AllowGlobalReassign"},
		},
		{
			Name:     "start",
			Category: "concept",
			Summary:  "Start here — a short tour of adssh",
			Description: `adssh is a shell that understands two languages at the same prompt:
ordinary shell commands, and Starlark, a small dialect of Python.

RUN A COMMAND
Type a command as in any shell, for example ls -la or git status. Pipes,
redirection and globs work (help shell).

RUN STARLARK
A line that looks like Starlark runs as Starlark: an assignment such as
x = 5, a def, for or if block, print(...), or a call such as
sys.getenv("HOME"). Variables stay set for the whole session (help starlark).

FORCE THE SHELL
Start a line with ! or with $ and a space to send it to the shell whatever it
looks like.

SECURITY
Every command, and every Starlark namespace call, is checked against the Rego
policy and written to the audit log before it runs (help policy).

MORE HELP
help shell: pipes, redirection, globs, and known limits.
help keys: line editing keys.
help starlark: a Starlark primer.
help adssh-starlark: what adssh adds to Starlark.
help search followed by a word: search every topic.
A command followed by --help: usage of a built-in command.
vbins: list the built-in commands.

LEAVE
Type exit, or press Ctrl-D on an empty line.`,
			Examples: []HelpExample{
				{Command: `ls -la`, Description: "a shell command"},
				{Command: `x = 5`, Description: "a Starlark assignment"},
				{Command: `print(x * 2)`, Description: "Starlark; prints 10"},
				{Command: `! echo forced`, Description: "always the shell"},
				{Command: `help keys`, Description: "line editing keys"},
				{Command: `exit`, Description: "leave adssh"},
			},
			SeeAlso: []string{"shell", "keys", "starlark", "adssh-starlark", "policy"},
			Tags:    []string{"start", "tour", "intro", "introduction", "getting started", "begin", "new"},
		},
		{
			Name:     "shell",
			Category: "concept",
			Summary:  "Shell lines — pipes, redirection, globs, and known limits",
			Description: `Shell lines run in an embedded POSIX shell with bash extensions. Every
simple command is checked by the policy before it runs.

WHAT WORKS
Pipelines: cmd1 | cmd2
Lists: cmd1 && cmd2, cmd1 || cmd2, cmd1 ; cmd2
Output to a file: > file, and >> file to append
Input from a file: < file
Here-documents: << EOF, and <<- EOF, which removes leading tabs
Here-strings: <<< "text"
Standard error: 2> file, >&2, and 2>&1
Globs: *, ? and [abc]
Home directory: ~ and ~/dir
Command substitution: $(command)
Process substitution: <(command)
Background: cmd & and wait. There is no job table, so background jobs are
not listed.

KNOWN LIMITS
File descriptors 3 and above are not supported. A line with a redirection
such as 3> file, 4< file or exec 3> file is refused before any of it runs,
with "unsupported redirect fd 3". Opening /dev/fd/3 or higher is refused
with an error.
adssh -c exits with the command's own status, as sh -c does: exit 3 exits 3.
exit N at the prompt ends the session with status N.
In restricted mode cd, export, and command names that contain / are refused
(help restricted).`,
			Examples: []HelpExample{
				{Command: `ls -la | grep go`, Description: "a pipeline"},
				{Command: `make && echo built || echo failed`, Description: "and, or"},
				{Command: `date > now.txt`, Description: "write a file"},
				{Command: `date >> log.txt`, Description: "append to a file"},
				{Command: `sort < names.txt`, Description: "read a file"},
				{Command: `grep x <<< "a x b"`, Description: "here-string"},
				{Command: `ls missing 2>&1 | grep -i no`, Description: "errors into the pipe"},
				{Command: `echo $(hostname) ~`, Description: "substitution and home"},
				{Command: `diff <(ls a) <(ls b)`, Description: "process substitution"},
			},
			SeeAlso: []string{"start", "keys", "restricted", "starlark"},
			Tags:    []string{"shell", "pipe", "pipeline", "redirect", "redirection", "glob", "heredoc", "fd", "descriptor"},
		},
		{
			Name:     "keys",
			Category: "concept",
			Summary:  "Line editing keys — emacs and vi, history search, suggestions",
			Description: `adssh uses emacs keys unless you choose vi. Choose with set_keymap("vi")
or set_keymap("emacs"), at the prompt or in ~/.adsshrc.

IN BOTH KEYMAPS
Enter: run the line.
Tab: complete command names, file names, and Starlark names, for example
sys.ge to sys.getenv.
Ctrl-R: search history backward. Ctrl-S searches forward.
Up and Down arrows: previous and next history line.
Right arrow or Ctrl-F at the end of the line: accept the dimmed history
suggestion.
Ctrl-L: clear the screen.
Ctrl-C: at the prompt, discard the line. While Starlark runs, stop it.
Ctrl-D: on an empty line, leave adssh. Otherwise delete the character
under the cursor.

EMACS KEYS
Ctrl-A: start of line. Ctrl-E: end of line.
Ctrl-B and Ctrl-F: back and forward one character.
Alt-B and Alt-F: back and forward one word.
Ctrl-P and Ctrl-N: previous and next history line.
Ctrl-K: delete to the end of the line. Ctrl-U: delete to the start.
Ctrl-W or Alt-Backspace: delete the word before the cursor.
Alt-D: delete the word after the cursor.
Ctrl-T: swap two characters. Ctrl-Y: paste the last deleted text.

VI KEYS
Esc enters command mode. i, a, I and A return to insert mode.
In command mode: h and l move, w, b and e move by word, 0, ^ and $ go to the
start or end of the line, j and k walk history, x deletes a character, dd
deletes the line, dw deletes a word, cw and cc change, r replaces one
character, f and t find a character, p pastes.
In insert mode the keys listed under IN BOTH KEYMAPS still work.

SUGGESTIONS
As you type, adssh can show the rest of a matching history line, dimmed,
after the cursor. Turn it on or off with set suggest on and set suggest off.
ADSSH_SUGGEST=on or off sets the starting state. The default is on in a
local session and off in an SSH session, where a screen reader would read
the dimmed text aloud.
set highlight on colors dangerous commands before you press Enter. It needs
a terminal and is off by default; ADSSH_HIGHLIGHT=1 turns it on at start.`,
			Examples: []HelpExample{
				{Command: `set_keymap("vi")`, Description: "vi keys"},
				{Command: `set_keymap("emacs")`, Description: "emacs keys (the default)"},
				{Command: `set suggest off`, Description: "no dimmed history suggestions"},
				{Command: `set highlight on`, Description: "color dangerous commands"},
			},
			SeeAlso: []string{"start", "history", "prompt"},
			Tags:    []string{"keys", "keyboard", "emacs", "vi", "vim", "readline", "ctrl", "shortcut", "suggest", "completion", "tab"},
		},
		{
			Name:     "vbin",
			Category: "concept",
			Summary:  "Virtual binaries — built-in commands with no external dependency",
			Description: `Virtual binaries (VBINs) are commands implemented directly in the adssh
binary. They behave like external commands but require no separate installation.

VBINs are resolved before PATH lookup, so they shadow any external command
with the same name.

ADDING A VBIN:
  1. Create a struct implementing the VirtualBinary interface in package security:
       Name() string
       Description() string
       Usage() string
       Run(ctx context.Context, args []string) error
  2. Register it in init():
       func init() { Register(myBinary{}) }

The --help flag is handled automatically by DispatchVBin.`,
			Examples: []HelpExample{
				{Command: "vbins", Description: "list all registered virtual binaries"},
				{Command: "stty --help", Description: "show help for the stty vbin"},
				{Command: "help list vbin", Description: "list all vbins via help system"},
			},
			SeeAlso: []string{"vbins", "hooks", "plugins"},
			Tags:    []string{"vbin", "virtual binary", "builtin", "command", "plugin"},
		},
		{
			Name:     "hooks",
			Category: "concept",
			Summary:  "Pre-exec and post-command hooks (__preexec__, __postcmd__)",
			Description: `Two Starlark functions run around every line typed at the interactive
prompt, shell or Starlark:
__preexec__(cmd) runs before the line, with the line as typed.
__postcmd__(cmd, code) runs after it, with its exit code.

Define them with def in a profile: /etc/adssh_profile (login shells),
~/.adsshprofile, or ~/.adsshrc. The prompt refuses to assign any name that
starts with __ and prints "adssh: not assigned (reserved)", so a hook
cannot be added or replaced from the prompt.

Hooks run only in the interactive shell, not for adssh -c or script files.
An error inside a hook is ignored.

The 4eyes and cm gates are not hooks. They are part of the command gate and
always run.`,
			Examples: []HelpExample{
				{Command: `def __preexec__(cmd):`, Description: "in ~/.adsshrc"},
				{Command: `    print("about to run:", cmd)`, Description: "body; end with an empty line"},
				{Command: `def __postcmd__(cmd, code):`, Description: "in ~/.adsshrc"},
				{Command: `    if code != 0: print("exit", code)`, Description: "report failures"},
			},
			SeeAlso: []string{"4eyes", "cm", "starlark", "adssh-starlark"},
			Tags:    []string{"hooks", "preexec", "postcmd", "callback", "event", "profile", "adsshrc"},
		},
		{
			Name:     "plugins",
			Category: "concept",
			Summary:  "Plugin system — extend adssh with Go shared libraries",
			Description: `adssh supports plugins as Go shared libraries (.so files) loaded at runtime.

A plugin implements the AdsshPlugin interface:
  Name() string
  Init(globals starlark.StringDict) error

Load a plugin from Starlark:
  sys.load_plugin("/path/to/plugin.so")

Once loaded, the plugin's exported Starlark values are available in the
globals dict under the plugin's Name().

Starlark plugins live in ~/.adssh/plugins/<name>/ as manifest.yaml and plugin.star. Nothing loads until plugin load <name> or sys.load_plugins. Restricted mode refuses that load. A Go .so still uses sys.load_plugin.`,
			Examples: []HelpExample{
				{Command: `sys.load_plugin("/opt/adssh/plugins/mycloud.so")`, Description: "load a plugin"},
				{Command: `plugins["mycloud"].list_resources()`, Description: "use a loaded plugin"},
				{Command: `plugin load hello`, Description: "load a checked Starlark plugin"},
			},
			SeeAlso: []string{"sys", "vbin", "starlark"},
			Tags:    []string{"plugins", "extensions", "shared library", "so", "load_plugin"},
		},
		{
			Name:     "history",
			Category: "concept",
			Summary:  "History expansion — !!, !-N, !prefix, ^old^new",
			Description: `adssh supports Bash-compatible history expansion:

  !!         — repeat last command
  !-N        — repeat Nth most-recent command
  !prefix    — repeat last command starting with prefix
  ^old^new   — replace first occurrence of old with new in last command

The REPL saves history in ~/.adssh/history (override with ADSSH_HISTORY).
The history and fc vbins read ADSSH_HISTORY_FILE instead, falling back to
~/.adssh/history, so set both if you move the file.`,
			Examples: []HelpExample{
				{Command: "!!", Description: "re-run last command"},
				{Command: "!-2", Description: "re-run 2nd most-recent command"},
				{Command: "!git", Description: "re-run last git command"},
				{Command: "^typo^fix", Description: "correct typo in last command"},
				{Command: "history 20", Description: "show last 20 history entries"},
				{Command: "fc -l", Description: "list history (fc vbin)"},
			},
			SeeAlso: []string{"history", "fc"},
			Tags:    []string{"history", "expansion", "!!", "repeat", "recall"},
		},
		{
			Name:     "prompt",
			Category: "concept",
			Summary:  "Prompt customization — the PROMPT Starlark variable and escapes",
			Description: `PROMPT is a Starlark variable, not an environment variable, so export does
not change it. Assign it in ~/.adsshrc or at the prompt. It is read before
every prompt. RPROMPT, if set, is drawn at the right edge of the line.

Escapes. Inside a normal Starlark string write each backslash twice, as in
the examples.
\u: user name
\h: host name up to the first dot
\H: full host name
\w: working directory, with ~ for home
\W: last part of the working directory
\$: # for root, otherwise $
\t: time as HH:MM:SS
\d: date, such as Mon Jan 02
\n: new line
\e: the escape character, for colors
\g: git branch, when set gitprompt on or ADSSH_GIT_PROMPT=1
%~: same as \w
$(expr): the value of a Starlark expression
\[ and \] are accepted and removed.

Colors: put ANSI codes in the string, for example "\x1b[32m" for green and
"\x1b[0m" to reset.`,
			Examples: []HelpExample{
				{Command: `PROMPT = "\\u@\\h:\\w\\$ "`, Description: "user@host:dir$"},
				{Command: `PROMPT = "\x1b[32m\\u@\\h\x1b[0m:\\w\\$ "`, Description: "green user@host"},
				{Command: `RPROMPT = "\\t"`, Description: "time at the right edge"},
			},
			SeeAlso: []string{"keys", "start"},
			// nolint:misspell // "customise"/"colour" kept intentionally alongside their
			// American spellings so help search matches either variant.
			Tags: []string{"prompt", "PS1", "PROMPT", "RPROMPT", "terminal", "customise", "customize", "colour", "color"},
		},
	}

	for _, e := range entries {
		RegisterHelp(e)
	}
}
