//go:build ee

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

// command is one adsshadm verb. The same table drives one-shot mode, the
// prompt, help, and completion, so the three cannot drift apart.
type command struct {
	name string
	args string // usage after the name
	help string
	// prompt, when set, marks a state-changing command. dispatch calls it
	// and asks the operator (or requires --yes) before run. It returns ""
	// when these particular arguments change nothing (guard with no args).
	prompt  func(ctx context.Context, a *app, args []string) (string, error)
	run     func(ctx context.Context, a *app, args []string) error
	suggest func(ctx context.Context, a *app, argIndex int) []string // live values for completion
}

// app is one adsshadm run: the client, output, and global switches.
type app struct {
	c       *client
	out     io.Writer
	jsonOut bool
	yes     bool
	confirm func(prompt string) bool
	snoop   func(ctx context.Context, a *app, req snoopRequest) error
}

func commands() []command {
	return []command{
		{name: "sessions", help: "list live sessions", run: runSessions},
		{name: "gateways", help: "list running gateways", run: listJSON("/v1/gateways")},
		{name: "approvals", help: "list pending four-eyes requests", run: runApprovals},
		{name: "approve", args: "<request-id>", help: "approve a pending request (named key)",
			prompt: decidePrompt("approve"), run: decide(true), suggest: suggestRequestIDs},
		{name: "deny", args: "<request-id>", help: "deny a pending request (named key)",
			prompt: decidePrompt("deny"), run: decide(false), suggest: suggestRequestIDs},
		{name: "explain", args: "<session-id> <command...>", help: "show how policy would decide a command",
			run: runExplain, suggest: suggestFirst(suggestSessionIDs)},
		{name: "evidence", args: "[session-id] [--since T] [--until T] [--change ID]", help: "export a verified evidence bundle",
			run: runEvidence, suggest: suggestFirst(suggestSessionIDs)},
		{name: "recordings", help: "list session recordings", run: listJSON("/v1/recordings")},
		{name: "elevations", help: "list elevations", run: listJSON("/v1/elevations")},
		{name: "leases", help: "list leases", run: listJSON("/v1/leases")},
		{name: "guard", args: "[unban <addr>]", help: "show the SSH jail, or unban an address (named key)",
			prompt: guardPrompt, run: runGuard, suggest: suggestGuard},
		{name: "snoop", args: "<session-id> <user> [--rw] --purpose support|investigation --reason TEXT",
			help: "attach to a live session, view-only unless --rw", prompt: snoopPrompt, run: runSnoop, suggest: suggestSnoop},
	}
}

func findCommand(name string) (command, bool) {
	for _, c := range commands() {
		if c.name == name {
			return c, true
		}
	}
	return command{}, false
}

// dispatch runs one command line already split into words.
func (a *app) dispatch(ctx context.Context, words []string) error {
	if len(words) == 0 {
		return nil
	}
	if words[0] == "help" {
		a.printHelp()
		return nil
	}
	cmd, ok := findCommand(words[0])
	if !ok {
		return fmt.Errorf("unknown command %q (try help)", words[0])
	}
	args := words[1:]
	if cmd.prompt != nil {
		question, err := cmd.prompt(ctx, a, args)
		if err != nil {
			return err
		}
		if question != "" {
			if err := a.confirmWrite(question); err != nil {
				return err
			}
		}
	}
	return cmd.run(ctx, a, args)
}

func (a *app) printHelp() {
	tw := tabwriter.NewWriter(a.out, 0, 2, 2, ' ', 0)
	for _, c := range commands() {
		fmt.Fprintf(tw, "  %s %s\t%s\n", c.name, c.args, c.help)
	}
	fmt.Fprintf(tw, "  help\tthis list\n")
	_ = tw.Flush()
}

func (a *app) printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.out, "%s\n", cleanJSON(b))
	return err
}

// confirmWrite asks before a state change unless --yes was given. With no
// terminal to ask on and no --yes, it refuses.
func (a *app) confirmWrite(prompt string) error {
	if a.yes {
		return nil
	}
	if a.confirm == nil {
		return errors.New("refusing a state change without a terminal to confirm on; pass --yes")
	}
	if !a.confirm(prompt) {
		return errors.New("canceled")
	}
	return nil
}

func listJSON(path string) func(context.Context, *app, []string) error {
	return func(ctx context.Context, a *app, args []string) error {
		if len(args) != 0 {
			return errors.New("takes no arguments")
		}
		var v any
		if err := a.c.do(ctx, "GET", path, nil, &v); err != nil {
			return err
		}
		return a.printJSON(v)
	}
}

// sessionInfo is the subset of internal/sys.SessionInfo adsshadm shows.
// The server encodes that struct without json tags, so keys are Go names.
type sessionInfo struct {
	ID             string
	User           string
	CreatedAt      time.Time
	LastActive     time.Time
	CurrentCommand string
	Terminated     bool
	Recording      string
	AgentID        string
}

func fetchSessions(ctx context.Context, a *app) ([]sessionInfo, error) {
	var s []sessionInfo
	err := a.c.do(ctx, "GET", "/v1/sessions", nil, &s)
	return s, err
}

func runSessions(ctx context.Context, a *app, args []string) error {
	if len(args) != 0 {
		return errors.New("takes no arguments")
	}
	if a.jsonOut {
		return listJSON("/v1/sessions")(ctx, a, nil)
	}
	s, err := fetchSessions(ctx, a)
	if err != nil {
		return err
	}
	sort.Slice(s, func(i, j int) bool { return s[i].ID < s[j].ID })
	tw := tabwriter.NewWriter(a.out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tUSER\tAGE\tIDLE\tRECORDING\tCOMMAND")
	now := time.Now()
	for _, x := range s {
		if x.Terminated {
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", clean(x.ID), dash(clean(x.User)), since(now, x.CreatedAt),
			since(now, x.LastActive), dash(clean(filepath.Base(x.Recording))), dash(clean(x.CurrentCommand)))
	}
	return tw.Flush()
}

type approval struct {
	RequestID string `json:"request_id"`
	Command   string `json:"command"`
	Requester string `json:"requester"`
	Hostname  string `json:"hostname"`
	Timestamp string `json:"timestamp"`
}

func runApprovals(ctx context.Context, a *app, args []string) error {
	if len(args) != 0 {
		return errors.New("takes no arguments")
	}
	if a.jsonOut {
		return listJSON("/v1/approvals")(ctx, a, nil)
	}
	var p []approval
	if err := a.c.do(ctx, "GET", "/v1/approvals", nil, &p); err != nil {
		return err
	}
	if len(p) == 0 {
		fmt.Fprintln(a.out, "no pending requests")
		return nil
	}
	tw := tabwriter.NewWriter(a.out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "REQUEST\tREQUESTER\tHOST\tWHEN\tCOMMAND")
	for _, x := range p {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", clean(x.RequestID), clean(x.Requester), clean(x.Hostname), clean(x.Timestamp), clean(x.Command))
	}
	return tw.Flush()
}

func decide(approve bool) func(context.Context, *app, []string) error {
	verb, path := "deny", "/v1/approvals/deny"
	if approve {
		verb, path = "approve", "/v1/approvals/approve"
	}
	return func(ctx context.Context, a *app, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("usage: %s <request-id>", verb)
		}
		var res map[string]any
		if err := a.c.do(ctx, "POST", path, map[string]string{"request_id": args[0]}, &res); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "%s %s as %s\n", clean(fmt.Sprint(res["action"])), clean(args[0]), clean(fmt.Sprint(res["approver"])))
		return nil
	}
}

// decidePrompt looks the request up so the operator confirms the command
// itself, not an opaque id, and refuses an id that is not pending.
func decidePrompt(verb string) func(context.Context, *app, []string) (string, error) {
	return func(ctx context.Context, a *app, args []string) (string, error) {
		if len(args) != 1 {
			return "", fmt.Errorf("usage: %s <request-id>", verb)
		}
		var pending []approval
		if err := a.c.do(ctx, "GET", "/v1/approvals", nil, &pending); err != nil {
			return "", err
		}
		for _, p := range pending {
			if p.RequestID == args[0] {
				return fmt.Sprintf("%s %s's request on %s to run:\n    %s\n%s?", verb, clean(p.Requester),
					clean(p.Hostname), clean(p.Command), verb), nil
			}
		}
		return "", fmt.Errorf("no pending request %s (see approvals)", clean(args[0]))
	}
}

func runExplain(ctx context.Context, a *app, args []string) error {
	if len(args) < 2 {
		return errors.New("usage: explain <session-id> <command...>")
	}
	var v any
	if err := a.c.do(ctx, "POST", "/v1/explain", map[string]any{"session_id": args[0], "command": args[1:]}, &v); err != nil {
		return err
	}
	return a.printJSON(v)
}

func runEvidence(ctx context.Context, a *app, args []string) error {
	filter := map[string]string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--since", "--until", "--change":
			if i+1 >= len(args) {
				return fmt.Errorf("%s needs a value", args[i])
			}
			key := map[string]string{"--since": "since", "--until": "until", "--change": "change_id"}[args[i]]
			filter[key] = args[i+1]
			i++
		default:
			if strings.HasPrefix(args[i], "-") || filter["session_id"] != "" {
				return fmt.Errorf("unexpected argument %q", args[i])
			}
			filter["session_id"] = args[i]
		}
	}
	var v any
	if err := a.c.do(ctx, "POST", "/v1/evidence", filter, &v); err != nil {
		return err
	}
	return a.printJSON(v)
}

type guardSnapshot struct {
	Enabled bool   `json:"enabled"`
	Tripped string `json:"tripped"`
	Note    string `json:"note"`
	Bans    []struct {
		Addr   string    `json:"addr"`
		Until  time.Time `json:"until"`
		Reason string    `json:"reason"`
	} `json:"bans"`
}

func runGuard(ctx context.Context, a *app, args []string) error {
	switch {
	case len(args) == 0:
		if a.jsonOut {
			return listJSON("/v1/guard")(ctx, a, nil)
		}
		var g guardSnapshot
		if err := a.c.do(ctx, "GET", "/v1/guard", nil, &g); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "enabled=%t", g.Enabled)
		if g.Tripped != "" {
			fmt.Fprintf(a.out, " tripped=%s", clean(g.Tripped))
		}
		if g.Note != "" {
			fmt.Fprintf(a.out, " (%s)", clean(g.Note))
		}
		fmt.Fprintln(a.out)
		if len(g.Bans) == 0 {
			fmt.Fprintln(a.out, "no bans")
			return nil
		}
		tw := tabwriter.NewWriter(a.out, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "ADDR\tUNTIL\tREASON")
		for _, b := range g.Bans {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", clean(b.Addr), b.Until.Format(time.RFC3339), clean(b.Reason))
		}
		return tw.Flush()
	case len(args) == 2 && args[0] == "unban":
		if err := a.c.do(ctx, "POST", "/v1/guard/unban", map[string]string{"addr": args[1]}, nil); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "unbanned %s\n", clean(args[1]))
		return nil
	}
	return errors.New("usage: guard [unban <addr>]")
}

// guardPrompt confirms only the unban form.
func guardPrompt(_ context.Context, _ *app, args []string) (string, error) {
	if len(args) == 2 && args[0] == "unban" {
		return fmt.Sprintf("unban %s?", clean(args[1])), nil
	}
	return "", nil
}

// Completion sources. Each is best-effort: an API error yields no suggestions.

func suggestRequestIDs(ctx context.Context, a *app, argIndex int) []string {
	if argIndex != 0 {
		return nil
	}
	var p []approval
	if a.c.do(ctx, "GET", "/v1/approvals", nil, &p) != nil {
		return nil
	}
	out := make([]string, 0, len(p))
	for _, x := range p {
		out = append(out, x.RequestID)
	}
	return out
}

func suggestSessionIDs(ctx context.Context, a *app) []string {
	s, err := fetchSessions(ctx, a)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(s))
	for _, x := range s {
		if !x.Terminated {
			out = append(out, x.ID)
		}
	}
	return out
}

func suggestFirst(f func(context.Context, *app) []string) func(context.Context, *app, int) []string {
	return func(ctx context.Context, a *app, argIndex int) []string {
		if argIndex != 0 {
			return nil
		}
		return f(ctx, a)
	}
}

func suggestGuard(ctx context.Context, a *app, argIndex int) []string {
	switch argIndex {
	case 0:
		return []string{"unban"}
	case 1:
		var g guardSnapshot
		if a.c.do(ctx, "GET", "/v1/guard", nil, &g) != nil {
			return nil
		}
		out := make([]string, 0, len(g.Bans))
		for _, b := range g.Bans {
			out = append(out, b.Addr)
		}
		return out
	}
	return nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func since(now, t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return now.Sub(t).Round(time.Second).String()
}
