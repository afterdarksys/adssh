package security

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/afterdarksys/adssh/internal/sys"
	"mvdan.cc/sh/v3/interp"
)

// Threats: whoami reads only the calling session (the ID the gate put in the
// context); it takes no session argument, so a caller cannot read another
// session's principals or elevation. --caps evaluates policy through
// ExplainCommand, which writes no audit record, opens no approval, and
// records no denial. In an SSH session process the policy lives in the
// listener, so --caps is refused there rather than reporting the empty
// local engine.

// WhoamiReport is the identity of one session and, with --caps, what it may do.
type WhoamiReport struct {
	User       string   `json:"user"`
	SessionID  string   `json:"session_id,omitempty"`
	Principals []string `json:"principals,omitempty"`
	// IdentitySource is how the user was established: "bound" (engine
	// binding), "login" (set when the session was created), a sys identity
	// source ("asserted", "device-login", "oidc-verified"), or "os" when
	// there is no session.
	IdentitySource string          `json:"identity_source"`
	Elevation      *ElevationClaim `json:"elevation,omitempty"`
	Agent          *AgentClaim     `json:"agent,omitempty"`
	Caps           *WhoamiCaps     `json:"caps,omitempty"`
}

// WhoamiCaps is the session's capability preview under the current policy.
type WhoamiCaps struct {
	Entitlements            []string      `json:"entitlements,omitempty"`
	EntitledCommands        []string      `json:"entitled_commands,omitempty"`
	EntitlementsConfigured  bool          `json:"entitlements_configured"`
	CapabilityGroupsAllowed []string      `json:"capability_groups_allowed"`
	CapabilityGroupsDenied  []string      `json:"capability_groups_denied"`
	Probes                  []WhoamiProbe `json:"probes"`
}

// WhoamiProbe is the ExplainCommand outcome for one representative command.
type WhoamiProbe struct {
	Command             string   `json:"command"`
	Args                []string `json:"args,omitempty"`
	Capability          string   `json:"capability,omitempty"`
	Outcome             string   `json:"outcome"`
	Rule                string   `json:"rule,omitempty"`
	Reason              string   `json:"reason,omitempty"`
	RequiredRole        string   `json:"required_role,omitempty"`
	RequiredEntitlement string   `json:"required_entitlement,omitempty"`
}

// whoamiCommandProbes is the fixed list of representative shell commands.
var whoamiCommandProbes = [][]string{
	{"ls"},
	{"cat", "/etc/hosts"},
	{"rm", "-rf", "/tmp/adssh-whoami-probe"},
	{"sudo", "true"},
	{"ssh", "host"},
	{"kubectl", "delete", "pod", "probe"},
	{"docker", "run", "probe"},
	{"git", "push"},
	{"mirror", "view", "probe"},
	{"mirror", "share", "--with", "probe", "--for", "10m"},
	{"elevate", "request", "probe-role", "--for", "10m", "--reason", "probe"},
	{"gateway", "open", "probe"},
}

// whoamiCapabilityProbes maps each capability group to a governed Starlark
// path that ClassifyCapabilities places in that group.
var whoamiCapabilityProbes = []struct{ capability, command string }{
	{CapNet, "starlark.net.dial"},
	{CapFileops, "starlark.fs.write"},
	{CapProc, "starlark.sys.exec_cmd"},
	{CapDatabases, "starlark.db.query"},
	{CapCloud, "starlark.aws.ec2"},
	{CapK8s, "starlark.k8s.apply"},
	{CapContainers, "starlark.containers.run"},
	{CapSecrets, "starlark.secrets.get"},
	{CapVCS, "starlark.vcs.push"},
	{CapNotify, "starlark.notify.send"},
	{CapCrypto, "starlark.crypto.sign"},
	{CapData, "starlark.data.parse"},
}

// Whoami reports the identity of sessionID and, when caps is set, the
// session's entitlements and a policy preview over the fixed probes.
func (e *Engine) Whoami(sessionID string, caps bool) (WhoamiReport, error) {
	if caps && RemoteGateProcess() {
		return WhoamiReport{}, fmt.Errorf("whoami: --caps is evaluated by the listener; not available in this process")
	}
	pctx := e.buildPolicyContext("whoami", nil, sessionID)
	if pctx.IdentityUnknown {
		return WhoamiReport{}, fmt.Errorf("whoami: session identity unknown")
	}
	report := WhoamiReport{
		User:       pctx.User,
		SessionID:  sessionID,
		Principals: pctx.Groups,
		Elevation:  pctx.Elevation,
		Agent:      pctx.Agent,
	}
	if pctx.Elevation != nil {
		// Groups carries the elevated role too; principals are the base set.
		report.Principals = pctx.Groups[:len(pctx.Groups)-1]
	}
	switch {
	case sessionID == "":
		report.IdentitySource = "os"
	case isBound(e, sessionID):
		report.IdentitySource = "bound"
	default:
		report.IdentitySource = "login"
		if session := sys.GetSession(sessionID); session != nil && session.IdentitySource() != "" {
			report.IdentitySource = session.IdentitySource()
		}
	}
	if !caps {
		return report, nil
	}

	c := &WhoamiCaps{
		EntitlementsConfigured:  e.hasEntitlements(),
		CapabilityGroupsAllowed: []string{},
		CapabilityGroupsDenied:  []string{},
	}
	if c.EntitlementsConfigured {
		c.Entitlements = e.EntitlementsHeld(pctx.User, pctx.Groups)
		c.EntitledCommands = e.EntitledCommands(pctx.User, pctx.Groups)
	}
	probe := func(args []string, capability string) (WhoamiProbe, error) {
		explanation, err := e.ExplainCommand(sessionID, args)
		if err != nil {
			return WhoamiProbe{}, err
		}
		p := WhoamiProbe{
			Command:             args[0],
			Args:                explanation.Args,
			Capability:          capability,
			Outcome:             explanation.Outcome,
			Rule:                explanation.Rule,
			RequiredRole:        explanation.RequiredRole,
			RequiredEntitlement: explanation.RequiredEntitlement,
		}
		for _, stage := range explanation.Stages {
			if stage.Status == "denied" {
				p.Reason = stage.Name + ": " + stage.Reason
				break
			}
		}
		return p, nil
	}
	for _, args := range whoamiCommandProbes {
		p, err := probe(args, "")
		if err != nil {
			return WhoamiReport{}, err
		}
		c.Probes = append(c.Probes, p)
	}
	for _, cp := range whoamiCapabilityProbes {
		p, err := probe([]string{cp.command}, cp.capability)
		if err != nil {
			return WhoamiReport{}, err
		}
		c.Probes = append(c.Probes, p)
		if p.Outcome == "denied" {
			c.CapabilityGroupsDenied = append(c.CapabilityGroupsDenied, cp.capability)
		} else {
			c.CapabilityGroupsAllowed = append(c.CapabilityGroupsAllowed, cp.capability)
		}
	}
	report.Caps = c
	return report, nil
}

func isBound(e *Engine, sessionID string) bool {
	_, _, ok := e.boundIdentity(sessionID)
	return ok
}

type whoamiBinary struct{}

func (whoamiBinary) Name() string { return "whoami" }
func (whoamiBinary) Description() string {
	return "Print this session's user; -v shows the identity, --caps previews what policy and RBAC allow"
}
func (whoamiBinary) Usage() string { return "whoami [-v] [--caps] [--json]" }

func (whoamiBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	caps, jsonOutput, verbose := false, false, false
	for _, arg := range args[1:] {
		switch arg {
		case "-v", "--verbose":
			verbose = true
		case "--caps":
			caps = true
		case "--json":
			jsonOutput = true
		default:
			return fmt.Errorf("whoami: unknown argument %q; usage: %s", arg, whoamiBinary{}.Usage())
		}
	}
	report, err := engineFromContext(ctx).Whoami(SessionIDFromContext(ctx), caps)
	if err != nil {
		return err
	}
	if jsonOutput {
		encoder := json.NewEncoder(hc.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	if !verbose && !caps {
		// Plain whoami prints only the user, like the OS binary, so
		// $(whoami) keeps working in scripts.
		fmt.Fprintln(hc.Stdout, report.User)
		return nil
	}
	printWhoami(hc.Stdout, report)
	return nil
}

func printWhoami(out io.Writer, r WhoamiReport) {
	row := func(key, value string) { fmt.Fprintf(out, "%-26s %s\n", key+":", value) }
	list := func(values []string) string {
		if len(values) == 0 {
			return "-"
		}
		return strings.Join(values, ", ")
	}
	row("user", emptyDash(r.User))
	row("session", emptyDash(r.SessionID))
	row("principals", list(r.Principals))
	row("identity source", r.IdentitySource)
	if r.Elevation != nil {
		row("elevation", fmt.Sprintf("%s until %s (reason: %s)", r.Elevation.Role, r.Elevation.ExpiresAt, r.Elevation.Reason))
	} else {
		row("elevation", "-")
	}
	if r.Agent != nil {
		row("agent", fmt.Sprintf("%s kind=%s risk=%s", r.Agent.ID, r.Agent.Kind, r.Agent.Risk))
	} else {
		row("agent", "-")
	}
	if r.Caps == nil {
		return
	}
	c := r.Caps
	if c.EntitlementsConfigured {
		row("entitlements", list(c.Entitlements))
		row("entitled commands", list(c.EntitledCommands))
	} else {
		row("entitlements", "not configured")
	}
	row("capability groups allowed", list(c.CapabilityGroupsAllowed))
	row("capability groups denied", list(c.CapabilityGroupsDenied))
	fmt.Fprintln(out, "policy preview:")
	for _, p := range c.Probes {
		name := strings.TrimSpace(p.Command + " " + strings.Join(p.Args, " "))
		if p.Capability != "" {
			name = p.Capability + " (" + p.Command + ")"
		}
		fmt.Fprintf(out, "  %-18s %s", p.Outcome, name)
		if p.Rule != "" {
			fmt.Fprintf(out, " rule=%s", p.Rule)
		}
		if p.RequiredRole != "" {
			fmt.Fprintf(out, " required_role=%s", p.RequiredRole)
		}
		if p.RequiredEntitlement != "" {
			fmt.Fprintf(out, " required_entitlement=%s", p.RequiredEntitlement)
		}
		if p.Reason != "" {
			fmt.Fprintf(out, " (%s)", p.Reason)
		}
		fmt.Fprintln(out)
	}
}

func init() { Register(whoamiBinary{}) }
