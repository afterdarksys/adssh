package security

// Threats: grid, flight, and agent commands, and worktree create, destroy,
// and checkout, require a live gridops elevation; a managed agent cannot
// mint that elevation. A managed agent may check out only into its own
// worktree and only from the source bound to its flight, and may cat only
// its own worktree. Membership tokens are never printed. Remote flights send
// no caller user, no credentials, and no source. Checkout and cat stay
// inside the scratch worktree.
// Non-goals: this does not execute a rehearsed command, skip policy, or
// change the process uid. repo cat by a non-agent session needs no
// elevation; it reads only inside the 0700 scratch root.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
	"mvdan.cc/sh/v3/interp"
)

type gridBinary struct{}
type flightBinary struct{}
type agentBinary struct{}
type worktreeBinary struct{}
type repoBinary struct{}

func (gridBinary) Name() string { return "grid" }
func (gridBinary) Description() string {
	return "sah-grid membership on a loopback TLS listener"
}
func (gridBinary) Usage() string {
	return `grid status
grid init [--id ID] [--token-file PATH | --token-out PATH]
grid serve --listen 127.0.0.1:0 --cert CERT --key KEY --token-file PATH
grid drain`
}

func (flightBinary) Name() string { return "flight" }
func (flightBinary) Description() string {
	return "Place, rehearse, and cancel a supervised cloud-agent flight"
}
func (flightBinary) Usage() string {
	return `flight place --id F --agent A --worktree W --for 10m [--source PATH]
flight place --id F --agent A --worktree W --for 10m --host URL --ca PATH [--server-name NAME] --token-file PATH
flight rehearse --id F -- command [arg...]
flight cancel --id F
flight status --id F`
}

func (agentBinary) Name() string { return "agent" }
func (agentBinary) Description() string {
	return "List supervised cloud agents on this host"
}
func (agentBinary) Usage() string { return "agent status" }

func (worktreeBinary) Name() string { return "worktree" }
func (worktreeBinary) Description() string {
	return "Create, destroy, or pin a scratch worktree"
}
func (worktreeBinary) Usage() string {
	return `worktree create --id W
worktree destroy --id W
worktree checkout --id W [--from PATH] --rev SHA`
}

func (repoBinary) Name() string { return "repo" }
func (repoBinary) Description() string {
	return "Read a file from a scratch worktree"
}
func (repoBinary) Usage() string { return "repo cat --id W --path REL" }

func init() {
	Register(gridBinary{})
	Register(flightBinary{})
	Register(agentBinary{})
	Register(worktreeBinary{})
	Register(repoBinary{})
}

func requireGridOps(ctx context.Context, command string) (*sys.Session, error) {
	session := sys.GetSession(SessionIDFromContext(ctx))
	if session == nil || session.ManagedAgent() != nil {
		return nil, fmt.Errorf("%s: requires an active gridops elevation", command)
	}
	elevation := session.ActiveElevation()
	if elevation == nil || elevation.Role != RoleGridOps {
		return nil, fmt.Errorf("%s: requires an active gridops elevation", command)
	}
	return session, nil
}

func (gridBinary) Run(ctx context.Context, args []string) error {
	if _, err := requireGridOps(ctx, "grid"); err != nil {
		return err
	}
	if len(args) < 2 {
		return fmt.Errorf("grid: usage: %s", gridBinary{}.Usage())
	}
	head, rest := splitDashDash(args[2:])
	if len(rest) > 0 {
		return fmt.Errorf("grid: unknown option %q", rest[0])
	}
	switch args[1] {
	case "status":
		if _, err := parseNamedFlags("grid", head, nil); err != nil {
			return err
		}
		id, fingerprint, listen, drained, flights, err := gridStatus()
		if err != nil {
			return err
		}
		hc := interp.HandlerCtx(ctx)
		fmt.Fprintf(hc.Stdout, "grid: id=%s fingerprint=%s drained=%t flights=%d listening=%s\n",
			id, fingerprint, drained, flights, emptyDash(listen))
		return nil
	case "init":
		flags, err := parseNamedFlags("grid", head, map[string]bool{
			"id": true, "token-file": true, "token-out": true,
		})
		if err != nil {
			return err
		}
		id, fingerprint, err := initGrid(flags["id"], flags["token-file"], flags["token-out"])
		if err != nil {
			return err
		}
		hc := interp.HandlerCtx(ctx)
		fmt.Fprintf(hc.Stdout, "grid: id=%s fingerprint=%s\n", id, fingerprint)
		return nil
	case "serve":
		return gridServe(ctx, head)
	case "drain":
		if _, err := parseNamedFlags("grid", head, nil); err != nil {
			return err
		}
		if err := drainGrid(); err != nil {
			return err
		}
		hc := interp.HandlerCtx(ctx)
		fmt.Fprintln(hc.Stdout, "grid: drained=true")
		return nil
	default:
		return fmt.Errorf("grid: unknown option %q", args[1])
	}
}

func gridServe(ctx context.Context, args []string) error {
	flags, err := parseNamedFlags("grid", args, map[string]bool{
		"listen": true, "cert": true, "key": true, "token-file": true,
	})
	if err != nil {
		return err
	}
	values := make([]string, 0, 4)
	for _, name := range []string{"listen", "cert", "key", "token-file"} {
		value, err := requiredFlag("grid", flags, name)
		if err != nil {
			return err
		}
		values = append(values, value)
	}
	url, err := listenGrid(values[0], values[1], values[2], values[3], engineFromContext(ctx))
	if err != nil {
		return err
	}
	hc := interp.HandlerCtx(ctx)
	fmt.Fprintf(hc.Stdout, "grid: listening %s\n", url)
	return nil
}

func (flightBinary) Run(ctx context.Context, args []string) error {
	session, err := requireGridOps(ctx, "flight")
	if err != nil {
		return err
	}
	if len(args) < 2 {
		return fmt.Errorf("flight: usage: %s", flightBinary{}.Usage())
	}
	head, rest := splitDashDash(args[2:])
	switch args[1] {
	case "place":
		if len(rest) > 0 {
			return fmt.Errorf("flight: unknown option %q", rest[0])
		}
		return flightPlace(ctx, session, head)
	case "rehearse":
		return flightRehearse(ctx, head, rest)
	case "cancel":
		if len(rest) > 0 {
			return fmt.Errorf("flight: unknown option %q", rest[0])
		}
		return flightCancel(ctx, head)
	case "status":
		if len(rest) > 0 {
			return fmt.Errorf("flight: unknown option %q", rest[0])
		}
		return flightStatusCmd(ctx, head)
	default:
		return fmt.Errorf("flight: unknown option %q", args[1])
	}
}

func flightPlace(ctx context.Context, session *sys.Session, args []string) error {
	flags, err := parseNamedFlags("flight", args, map[string]bool{
		"id": true, "agent": true, "worktree": true, "for": true, "source": true,
		"host": true, "ca": true, "server-name": true, "token-file": true,
	})
	if err != nil {
		return err
	}
	if err := rejectOrphanRemoteFlags(flags); err != nil {
		return err
	}
	id, err := requiredFlag("flight", flags, "id")
	if err != nil {
		return err
	}
	agent, err := requiredFlag("flight", flags, "agent")
	if err != nil {
		return err
	}
	worktree, err := requiredFlag("flight", flags, "worktree")
	if err != nil {
		return err
	}
	forRaw, err := requiredFlag("flight", flags, "for")
	if err != nil {
		return err
	}
	remote := flags["host"] != ""
	if remote && flags["source"] != "" {
		return fmt.Errorf("flight: --source cannot be sent to a remote host")
	}
	ttl, seconds, err := parseFlightTTL(forRaw, remote)
	if err != nil {
		return err
	}
	var result flightResult
	if remote {
		result, err = postFlight(engineFromContext(ctx), flightClientOpts{
			Host:       flags["host"],
			CAFile:     flags["ca"],
			ServerName: flags["server-name"],
			TokenFile:  flags["token-file"],
			Action:     "place",
			Wire: flightWire{
				Action:     "place",
				FlightID:   id,
				AgentID:    agent,
				WorktreeID: worktree,
				TTLSeconds: seconds,
			},
		})
	} else {
		result, err = placeFlight(placeOpts{
			FlightID:   id,
			AgentID:    agent,
			WorktreeID: worktree,
			TTL:        ttl,
			User:       session.User,
			Remote:     false,
			Engine:     engineFromContext(ctx),
			Source:     flags["source"],
		})
	}
	if err != nil {
		return err
	}
	hc := interp.HandlerCtx(ctx)
	fmt.Fprintf(hc.Stdout, "flight: id=%s session=%s status=placed\n", result.FlightID, result.SessionID)
	return nil
}

func flightRehearse(ctx context.Context, args, command []string) error {
	flags, err := parseNamedFlags("flight", args, map[string]bool{
		"id": true, "host": true, "ca": true, "server-name": true, "token-file": true,
	})
	if err != nil {
		return err
	}
	if err := rejectOrphanRemoteFlags(flags); err != nil {
		return err
	}
	id, err := requiredFlag("flight", flags, "id")
	if err != nil {
		return err
	}
	var result flightResult
	if flags["host"] != "" {
		result, err = postFlight(engineFromContext(ctx), flightClientOpts{
			Host:       flags["host"],
			CAFile:     flags["ca"],
			ServerName: flags["server-name"],
			TokenFile:  flags["token-file"],
			Action:     "rehearse",
			Wire: flightWire{
				Action:   "rehearse",
				FlightID: id,
				Command:  command,
			},
		})
		if err != nil {
			return err
		}
	} else {
		result, err = rehearseFlight(engineFromContext(ctx), id, command, false)
		if err != nil {
			return err
		}
		if result.Status == "denied" {
			return fmt.Errorf("flight: denied: %s", result.Reason)
		}
	}
	hc := interp.HandlerCtx(ctx)
	fmt.Fprintf(hc.Stdout, "flight: id=%s status=%s\n", result.FlightID, result.Status)
	return nil
}

func flightCancel(ctx context.Context, args []string) error {
	flags, err := parseNamedFlags("flight", args, map[string]bool{"id": true})
	if err != nil {
		return err
	}
	id, err := requiredFlag("flight", flags, "id")
	if err != nil {
		return err
	}
	result, err := cancelFlight(id, false)
	if err != nil {
		return err
	}
	hc := interp.HandlerCtx(ctx)
	fmt.Fprintf(hc.Stdout, "flight: id=%s status=cancelled\n", result.FlightID)
	return nil
}

func flightStatusCmd(ctx context.Context, args []string) error {
	flags, err := parseNamedFlags("flight", args, map[string]bool{"id": true})
	if err != nil {
		return err
	}
	id, err := requiredFlag("flight", flags, "id")
	if err != nil {
		return err
	}
	result, err := flightStatus(id, false)
	if err != nil {
		return err
	}
	hc := interp.HandlerCtx(ctx)
	if result.Reason != "" {
		fmt.Fprintf(hc.Stdout, "flight: id=%s status=%s reason=%s\n", result.FlightID, result.Status, result.Reason)
		return nil
	}
	fmt.Fprintf(hc.Stdout, "flight: id=%s status=%s\n", result.FlightID, result.Status)
	return nil
}

func (agentBinary) Run(ctx context.Context, args []string) error {
	if _, err := requireGridOps(ctx, "agent"); err != nil {
		return err
	}
	if len(args) < 2 || args[1] != "status" {
		return fmt.Errorf("agent: usage: %s", agentBinary{}.Usage())
	}
	head, rest := splitDashDash(args[2:])
	if len(rest) > 0 {
		return fmt.Errorf("agent: unknown option %q", rest[0])
	}
	if _, err := parseNamedFlags("agent", head, nil); err != nil {
		return err
	}
	records := listAgents()
	hc := interp.HandlerCtx(ctx)
	if len(records) == 0 {
		fmt.Fprintln(hc.Stdout, "agent: none")
		return nil
	}
	sort.Slice(records, func(i, j int) bool { return records[i].AgentID < records[j].AgentID })
	for _, rec := range records {
		fmt.Fprintf(hc.Stdout, "agent: id=%s flight=%s worktree=%s session=%s user=%s\n",
			rec.AgentID, rec.ID, rec.WorktreeID, rec.SessionID, rec.User)
	}
	return nil
}

func (worktreeBinary) Run(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("worktree: usage: %s", worktreeBinary{}.Usage())
	}
	head, rest := splitDashDash(args[2:])
	if len(rest) > 0 {
		return fmt.Errorf("worktree: unknown option %q", rest[0])
	}
	switch args[1] {
	case "create", "destroy":
		return worktreeCreateOrDestroy(ctx, args[1], head)
	case "checkout":
		return worktreeCheckout(ctx, head)
	default:
		return fmt.Errorf("worktree: unknown option %q", args[1])
	}
}

func worktreeCreateOrDestroy(ctx context.Context, verb string, args []string) error {
	flags, err := parseNamedFlags("worktree", args, map[string]bool{"id": true})
	if err != nil {
		return err
	}
	id, err := requiredFlag("worktree", flags, "id")
	if err != nil {
		return err
	}
	session, err := requireWorktreeSession(ctx)
	if err != nil {
		return err
	}
	if session.ManagedAgent() != nil {
		return fmt.Errorf("worktree: agents cannot %s a worktree", verb)
	}
	if _, err := requireGridOps(ctx, "worktree"); err != nil {
		return err
	}
	hc := interp.HandlerCtx(ctx)
	if verb == "destroy" {
		if err := destroyWorktree(id); err != nil {
			return err
		}
		fmt.Fprintf(hc.Stdout, "worktree: id=%s destroyed\n", id)
		return nil
	}
	path, err := createWorktree(id)
	if err != nil {
		return err
	}
	fmt.Fprintf(hc.Stdout, "worktree: id=%s path=%s\n", id, path)
	return nil
}

// worktreeCheckout pins a worktree to a commit. A gridops operator names
// the source; a managed agent gets the source bound to its flight.
func worktreeCheckout(ctx context.Context, args []string) error {
	flags, err := parseNamedFlags("worktree", args, map[string]bool{
		"id": true, "from": true, "rev": true,
	})
	if err != nil {
		return err
	}
	id, err := requiredFlag("worktree", flags, "id")
	if err != nil {
		return err
	}
	rev, err := requiredFlag("worktree", flags, "rev")
	if err != nil {
		return err
	}
	session, err := requireWorktreeSession(ctx)
	if err != nil {
		return err
	}
	var source string
	if agent := session.ManagedAgent(); agent != nil {
		if err := requireAgentWorktree(session, id, "worktree"); err != nil {
			return err
		}
		if source, err = agentCheckoutSource(agent, flags["from"]); err != nil {
			return err
		}
	} else {
		if _, err := requireGridOps(ctx, "worktree"); err != nil {
			return err
		}
		if source, err = requiredFlag("worktree", flags, "from"); err != nil {
			return err
		}
	}
	if err := checkoutWorktree(id, source, rev); err != nil {
		return err
	}
	hc := interp.HandlerCtx(ctx)
	fmt.Fprintf(hc.Stdout, "worktree: id=%s rev=%s\n", id, rev)
	return nil
}

func (repoBinary) Run(ctx context.Context, args []string) error {
	if len(args) < 2 || args[1] != "cat" {
		return fmt.Errorf("repo: usage: %s", repoBinary{}.Usage())
	}
	head, rest := splitDashDash(args[2:])
	if len(rest) > 0 {
		return fmt.Errorf("repo: unknown option %q", rest[0])
	}
	flags, err := parseNamedFlags("repo", head, map[string]bool{"id": true, "path": true})
	if err != nil {
		return err
	}
	id, err := requiredFlag("repo", flags, "id")
	if err != nil {
		return err
	}
	rel, err := requiredFlag("repo", flags, "path")
	if err != nil {
		return err
	}
	session := sys.GetSession(SessionIDFromContext(ctx))
	if session == nil {
		return fmt.Errorf("repo: requires an active registered session")
	}
	if err := requireAgentWorktree(session, id, "repo"); err != nil {
		return err
	}
	data, err := repoCat(id, rel)
	if err != nil {
		return err
	}
	hc := interp.HandlerCtx(ctx)
	_, err = hc.Stdout.Write(data)
	return err
}

func requireWorktreeSession(ctx context.Context) (*sys.Session, error) {
	session := sys.GetSession(SessionIDFromContext(ctx))
	if session == nil {
		return nil, fmt.Errorf("worktree: requires an active registered session")
	}
	return session, nil
}

func requireAgentWorktree(session *sys.Session, id, command string) error {
	agent := session.ManagedAgent()
	if agent == nil {
		return nil
	}
	if !time.Now().Before(agent.ExpiresAt) {
		return fmt.Errorf("%s: agent lease expired", command)
	}
	if agent.Worktree != id {
		return fmt.Errorf("%s: agent is bound to a different worktree", command)
	}
	return nil
}

func rejectOrphanRemoteFlags(flags map[string]string) error {
	if flags["host"] != "" {
		return nil
	}
	if flags["ca"] != "" || flags["server-name"] != "" || flags["token-file"] != "" {
		return fmt.Errorf("flight: --host is required")
	}
	return nil
}

func parseFlightTTL(raw string, remote bool) (time.Duration, int64, error) {
	ttl, err := time.ParseDuration(raw)
	if err != nil || ttl < time.Second || ttl > 24*time.Hour {
		return 0, 0, fmt.Errorf("flight: ttl is invalid")
	}
	if remote && ttl%time.Second != 0 {
		return 0, 0, fmt.Errorf("flight: ttl is invalid")
	}
	return ttl, int64(ttl / time.Second), nil
}

func splitDashDash(args []string) (head, rest []string) {
	for i, arg := range args {
		if arg == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

func parseNamedFlags(command string, args []string, valued map[string]bool) (map[string]string, error) {
	out := make(map[string]string)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") || len(arg) < 3 {
			return nil, fmt.Errorf("%s: unknown option %q", command, arg)
		}
		name := arg[2:]
		takes, ok := valued[name]
		if !ok {
			return nil, fmt.Errorf("%s: unknown option %q", command, arg)
		}
		if _, exists := out[name]; exists {
			return nil, fmt.Errorf("%s: unknown option %q", command, arg)
		}
		if !takes {
			out[name] = ""
			continue
		}
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
			return nil, fmt.Errorf("%s: %s requires a value", command, arg)
		}
		i++
		out[name] = args[i]
	}
	return out, nil
}

func requiredFlag(command string, flags map[string]string, name string) (string, error) {
	value, ok := flags[name]
	if !ok || value == "" {
		return "", fmt.Errorf("%s: --%s is required", command, name)
	}
	return value, nil
}
