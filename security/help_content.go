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
			Description: "Controls shell behaviour flags. Common flags: -e (exit on error), -u (error on unset variables), -x (trace commands), -o pipefail (fail on pipe errors).",
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
			Name:        "disown",
			Category:    "builtin",
			Summary:     "Remove jobs from the job table",
			Description: "Removes the specified jobs from the shell's job table so they are not affected by SIGHUP when the shell exits.",
			Usage:       "disown [%job | pid ...]",
			Examples: []HelpExample{
				{Command: "disown %1", Description: "disown job 1"},
				{Command: "disown -h %1", Description: "mark job 1 immune to SIGHUP"},
			},
			Tags: []string{"job", "background", "nohup", "disown"},
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

Policy files are loaded at startup via ADSSH_POLICY_FILE or by calling
LoadPolicy() from Starlark. Decisions are recorded in the audit log.`,
			Usage: "ADSSH_POLICY_FILE=/path/to/policy.rego adssh",
			Examples: []HelpExample{
				{Command: `package adssh
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
			Description: `Restricted mode prevents certain operations that could compromise security:
  • cd to directories outside the allowed set
  • Setting or unsetting PATH, SHELL, ENV, BASH_ENV
  • Executing commands with / in the name
  • Redirecting output

Enable restricted mode with the -r flag or ADSSH_RESTRICTED=1 env var.
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
Chain file:   ~/.adssh/audit_chain.jsonl

Remote SIEM forwarding is configured via ADSSH_AUDIT_URL and
ADSSH_AUDIT_TOKEN environment variables.

Syslog forwarding is enabled via ADSSH_SYSLOG=auth|daemon|local0..7.

Each chain entry contains: type, source, command, user, timestamp, prev_hash, hash.`,
			Usage: "ADSSH_AUDIT_LOG=/var/log/adssh.log adssh\nADSSH_AUDIT_URL=https://siem/ ADSSH_AUDIT_TOKEN=xxx adssh",
			Examples: []HelpExample{
				{Command: "audit list", Description: "show recent audit entries (vbin)"},
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
If approved the command proceeds; if denied or timed out it is cancelled.

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
cm get
cm clear`,
			Examples: []HelpExample{
				{Command: "cm set CHG0012345", Description: "associate ticket with session"},
				{Command: "cm get", Description: "show current ticket ID"},
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
file I/O, process execution, plugin loading, and terminal control.`,
			Usage: "sys.<method>(args...)",
			Examples: []HelpExample{
				{Command: "sys.getenv('HOME')", Description: "read HOME env var"},
				{Command: "sys.setenv('DEBUG', '1')", Description: "set env var"},
				{Command: "sys.read_file('/etc/hostname')", Description: "read file contents"},
				{Command: "sys.write_file('/tmp/out.txt', 'hello')", Description: "write file"},
				{Command: "sys.exec_cmd(['ls', '-la'])", Description: "execute command"},
				{Command: "sys.exec_async(['tail', '-f', '/var/log/syslog'])", Description: "run async"},
				{Command: "sys.exec_json(['jq', '.key', 'file.json'])", Description: "exec, parse JSON output"},
				{Command: "sys.load_plugin('/path/to/plugin.so')", Description: "load a plugin"},
				{Command: "sys.register_command('myfn', handler)", Description: "register custom command"},
			},
			SeeAlso: []string{"plugins", "hooks"},
			Tags:    []string{"sys", "system", "env", "file", "exec", "process", "plugin"},
		},
		{
			Name:     "net",
			Category: "starlark",
			Summary:  "Network — HTTP requests and TCP connections",
			Description: "The net namespace provides HTTP GET and TCP send operations.",
			Usage:    "net.<method>(args...)",
			Examples: []HelpExample{
				{Command: "net.http_get('https://api.example.com/status')", Description: "HTTP GET"},
				{Command: "net.tcp_send('localhost:9000', 'PING')", Description: "raw TCP send"},
				{Command: "net.dial('tcp', 'localhost:22')", Description: "dial a TCP connection"},
				{Command: "net.dial_tls('tcp', 'example.com:443')", Description: "dial with TLS"},
			},
			Tags: []string{"net", "network", "http", "tcp", "tls", "request"},
		},
		{
			Name:     "crypto",
			Category: "starlark",
			Summary:  "Cryptographic hashing — MD5, SHA-256",
			Description: "The crypto namespace provides hashing functions.",
			Usage:    "crypto.<method>(data)",
			Examples: []HelpExample{
				{Command: "crypto.md5('hello')", Description: "compute MD5 hex digest"},
				{Command: "crypto.sha256('hello')", Description: "compute SHA-256 hex digest"},
			},
			Tags: []string{"crypto", "hash", "md5", "sha256", "checksum"},
		},
		{
			Name:     "data",
			Category: "starlark",
			Summary:  "Data serialisation — JSON and YAML parse/dump",
			Description: "The data namespace converts between Starlark values and JSON/YAML strings.",
			Usage:    "data.<method>(value)",
			Examples: []HelpExample{
				{Command: `data.json_parse('{"key":"value"}')`, Description: "parse JSON string"},
				{Command: "data.json_dump({'key': 'value'})", Description: "serialise to JSON"},
				{Command: "data.yaml_parse('key: value')", Description: "parse YAML string"},
				{Command: "data.yaml_dump({'key': 'value'})", Description: "serialise to YAML"},
			},
			Tags: []string{"data", "json", "yaml", "parse", "serialise", "serialize"},
		},
		{
			Name:     "re",
			Category: "starlark",
			Summary:  "Regular expressions — Go regexp and PCRE matching",
			Description: "The re namespace provides regex match functions using Go's regexp syntax and PCRE.",
			Usage:    "re.<method>(pattern, string)",
			Examples: []HelpExample{
				{Command: `re.match(r"^v\d+\.\d+", "v1.2.3")`, Description: "match with Go regexp"},
				{Command: `re.pcre_match(r"(?i)hello", "HELLO")`, Description: "case-insensitive PCRE match"},
			},
			Tags: []string{"re", "regex", "regexp", "pcre", "pattern", "match"},
		},
		{
			Name:     "sec",
			Category: "starlark",
			Summary:  "Security primitives — audit, restriction checks, file hashing, policy",
			Description: "The sec namespace exposes security primitives for Starlark scripts.",
			Usage:    "sec.<method>(args...)",
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
			Name:     "oci",
			Category: "starlark",
			Summary:  "Oracle Cloud Infrastructure — Compute and Object Storage",
			Description: "The oci namespace provides access to OCI Compute instances and Object Storage.",
			Usage:    "oci.<service>.<method>(args...)",
			Examples: []HelpExample{
				{Command: `oci.compute.list_instances("compartment-ocid")`, Description: "list OCI instances"},
				{Command: `oci.compute.start_instance("instance-ocid")`, Description: "start OCI instance"},
				{Command: `oci.storage.list_buckets("namespace", "compartment-ocid")`, Description: "list buckets"},
			},
			Tags: []string{"oci", "oracle", "cloud", "compute", "storage"},
		},
		{
			Name:     "git",
			Category: "starlark",
			Summary:  "Git operations — clone, status, commit, push, pull",
			Description: "The git namespace wraps go-git to provide repository operations from Starlark.",
			Usage:    "git.<method>(args...)",
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
			Name:     "github",
			Category: "starlark",
			Summary:  "GitHub API — repos, PRs, issues, releases, workflows",
			Description: "The github namespace provides GitHub API operations. Set GITHUB_TOKEN for authentication.",
			Usage:    "github.<method>(args...)",
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
			Name:     "k8s",
			Category: "starlark",
			Summary:  "Kubernetes — pods, deployments, services, namespaces, events",
			Description: "The k8s namespace provides Kubernetes cluster operations via the in-cluster or kubeconfig credentials.",
			Usage:    "k8s.<resource>(...)",
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
			Name:     "docker",
			Category: "starlark",
			Summary:  "Docker Engine API — containers, images, networks, volumes",
			Description: "The docker namespace wraps the Docker Engine API for container management.",
			Usage:    "docker.<method>(args...)",
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
			Name:     "secrets",
			Category: "starlark",
			Summary:  "Secrets management — Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager",
			Description: "The secrets namespace provides a unified interface to multiple secrets backends.",
			Usage:    "secrets.<backend>.<method>(args...)",
			Examples: []HelpExample{
				{Command: `secrets.vault.get("secret/myapp/db_password")`, Description: "read from Vault"},
				{Command: `secrets.aws.get("prod/myapp/api_key")`, Description: "read from AWS Secrets Manager"},
				{Command: `secrets.az.get("my-keyvault", "db-password")`, Description: "read from Azure Key Vault"},
				{Command: `secrets.gcp.get("my-project", "db-password")`, Description: "read from GCP Secret Manager"},
			},
			Tags: []string{"secrets", "vault", "aws", "azure", "gcp", "credentials", "password"},
		},
		{
			Name:     "db",
			Category: "starlark",
			Summary:  "Database clients — PostgreSQL, MySQL, Redis",
			Description: "The db namespace provides database connection helpers.",
			Usage:    "db.<engine>.<method>(args...)",
			Examples: []HelpExample{
				{Command: `db.postgres.query("postgres://user:pw@host/db", "SELECT 1")`, Description: "Postgres query"},
				{Command: `db.mysql.query("user:pw@tcp(host:3306)/db", "SELECT 1")`, Description: "MySQL query"},
				{Command: `db.redis.get("redis://localhost:6379", "mykey")`, Description: "Redis get"},
			},
			Tags: []string{"db", "database", "postgres", "mysql", "redis", "sql", "query"},
		},
		{
			Name:     "notify",
			Category: "starlark",
			Summary:  "Notifications — Slack, webhook, PagerDuty, Teams",
			Description: "The notify namespace sends notifications to various channels.",
			Usage:    "notify.<channel>.<method>(args...)",
			Examples: []HelpExample{
				{Command: `notify.slack.send("https://hooks.slack.com/...", "Deploy complete")`, Description: "Slack notification"},
				{Command: `notify.webhook.post("https://...", {"text": "alert"})`, Description: "generic webhook"},
				{Command: `notify.pagerduty.trigger("routing-key", "incident title")`, Description: "PagerDuty alert"},
				{Command: `notify.teams.send("https://...", "Deploy complete")`, Description: "Teams notification"},
			},
			Tags: []string{"notify", "slack", "pagerduty", "teams", "webhook", "alert", "notification"},
		},
		{
			Name:     "template",
			Category: "starlark",
			Summary:  "Go text/template rendering",
			Description: "The template namespace renders Go text/template strings and files.",
			Usage:    "template.<method>(args...)",
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
			Summary:  "Embedded Starlark scripting — when lines are Starlark vs shell",
			Description: `adssh embeds Starlark (a Python-like scripting language designed for
configuration) as a first-class citizen alongside traditional shell commands.

HOW THE PARSER DECIDES:
  A line is parsed as Starlark when:
    • it contains = outside of shell assignment context (e.g. x = 1 + 2)
    • it starts with a known Starlark keyword (def, for, if, load, ...)
    • it references a known namespace (sys., aws., k8s., ...)

  Otherwise the line is executed as a shell command.

WHY STARLARK:
  Starlark is deterministic, has no network/disk side-effects by default,
  and has a well-defined evaluation model making it safe for untrusted scripts.
  It also has first-class support for functions, loops, and data structures.

MULTI-LINE MODE:
  Enter multi-line Starlark with a line ending in ':' or '\'. Exit with a
  blank line or Ctrl-D.`,
			SeeAlso: []string{"sys", "net", "aws", "vbin", "hooks"},
			Tags:    []string{"starlark", "scripting", "language", "python", "mode", "eval"},
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
			Summary:  "Pre-exec and post-command hooks",
			Description: `adssh supports hooks that fire before and after each command:

  preexec  — called before a command is executed
  postcmd  — called after a command completes

Hooks are registered from Starlark using sys.register_command or by setting
the __preexec__ and __postcmd__ globals.

The 4eyes and CM systems are implemented as preexec hooks.`,
			Examples: []HelpExample{
				{Command: `def preexec(cmd): print("about to run:", cmd)`, Description: "define a preexec hook"},
				{Command: `__preexec__ = preexec`, Description: "register the hook"},
			},
			SeeAlso: []string{"4eyes", "cm", "vbin", "starlark"},
			Tags:    []string{"hooks", "preexec", "postcmd", "callback", "event"},
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
globals dict under the plugin's Name().`,
			Examples: []HelpExample{
				{Command: `sys.load_plugin("/opt/adssh/plugins/mycloud.so")`, Description: "load a plugin"},
				{Command: `plugins["mycloud"].list_resources()`, Description: "use a loaded plugin"},
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

History is stored in ~/.adssh/history (override with ADSSH_HISTORY_FILE).
The history vbin and fc vbin provide history management.`,
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
			Summary:  "Prompt customization — PROMPT variable and escape sequences",
			Description: `The shell prompt is controlled by the PROMPT environment variable.
Escape sequences are expanded at each prompt display:

  \\u   current username
  \\h   hostname (short)
  \\H   hostname (FQDN)
  \\w   current working directory (~ for home)
  \\W   basename of current working directory
  \\$   $ for regular user, # for root
  \\t   current time HH:MM:SS
  \\d   current date
  \\n   newline
  \\[   begin non-printing sequence (for ANSI codes)
  \\]   end non-printing sequence

ANSI colour codes work inside \\[...\\] sequences.`,
			Examples: []HelpExample{
				{Command: `export PROMPT='\u@\h:\w\$ '`, Description: "user@host:dir$ prompt"},
				{Command: `export PROMPT='\[\033[1;32m\]\u@\h\[\033[0m\]:\w\$ '`, Description: "green user@host"},
			},
			Tags: []string{"prompt", "PS1", "PROMPT", "terminal", "customise", "customize", "colour", "color"},
		},
	}

	for _, e := range entries {
		RegisterHelp(e)
	}
}
