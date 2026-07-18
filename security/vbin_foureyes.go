package security

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"mvdan.cc/sh/v3/interp"
)

// fourEyesBinary implements the 4eyes virtual binary for managing dual-approval rules.
//
// Subcommands:
//
//	4eyes add <pattern> [--approver user] [--ttl seconds]  — add a rule
//	4eyes remove <pattern>                                  — remove a rule
//	4eyes list                                              — show rules + pending
//	4eyes approve <token>                                   — approve a pending request
//	4eyes deny <token>                                      — deny a pending request
//	4eyes pending                                           — list all pending requests with age
//	4eyes test <command>                                    — dry-run: would this require approval?
type fourEyesBinary struct{}

func (fourEyesBinary) Name() string { return "4eyes" }
func (fourEyesBinary) Description() string {
	return "4-eyes dual-approval gate — SOX/PCI/FedRAMP compliant command hold"
}
func (fourEyesBinary) Usage() string {
	return "4eyes <add|remove|list|approve|deny|pending|test> [args]"
}

const (
	ansiGray = "\033[90m"
)

func (fourEyesBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)

	if len(args) < 2 {
		return printFourEyesHelp(ctx)
	}

	switch args[1] {

	// ── add ────────────────────────────────────────────────────────────────
	case "add":
		if len(args) < 3 {
			return fmt.Errorf("4eyes add: usage: 4eyes add <pattern> [--approver user] [--ttl seconds]")
		}
		pattern := args[2]
		approver := ""
		ttl := 300
		for i := 3; i < len(args); i++ {
			switch args[i] {
			case "--approver":
				if i+1 >= len(args) {
					return fmt.Errorf("4eyes add: --approver requires a value")
				}
				i++
				approver = args[i]
			case "--ttl":
				if i+1 >= len(args) {
					return fmt.Errorf("4eyes add: --ttl requires a value")
				}
				i++
				n, err := strconv.Atoi(args[i])
				if err != nil || n <= 0 {
					return fmt.Errorf("4eyes add: --ttl must be a positive integer")
				}
				ttl = n
			default:
				return fmt.Errorf("4eyes add: unknown flag %q", args[i])
			}
		}
		if err := AddFourEyesRule(pattern, approver, ttl); err != nil {
			return err
		}
		fmt.Fprintf(hc.Stdout, "%s%s✓%s Rule added: pattern=%q approver=%q ttl=%ds\n",
			ansiBold, ansiGreen, ansiReset, pattern, approver, ttl)
		return nil

	// ── remove ─────────────────────────────────────────────────────────────
	case "remove", "rm":
		if len(args) < 3 {
			return fmt.Errorf("4eyes remove: usage: 4eyes remove <pattern>")
		}
		pattern := args[2]
		if err := RemoveFourEyesRule(pattern); err != nil {
			return err
		}
		fmt.Fprintf(hc.Stdout, "%s%s✓%s Rule removed: %q\n", ansiBold, ansiGreen, ansiReset, pattern)
		return nil

	// ── list ───────────────────────────────────────────────────────────────
	case "list", "ls":
		return fourEyesList(ctx)

	// ── approve ────────────────────────────────────────────────────────────
	case "approve":
		if len(args) < 3 {
			return fmt.Errorf("4eyes approve: usage: 4eyes approve <token>")
		}
		token := args[2]
		if err := engineFromContext(ctx).ApproveRequestAs(token, approvalActor(SessionIDFromContext(ctx))); err != nil {
			return err
		}
		fmt.Fprintf(hc.Stdout, "%s%s✓%s Approved request: %s\n", ansiBold, ansiGreen, ansiReset, token)
		return nil

	// ── deny ───────────────────────────────────────────────────────────────
	case "deny":
		if len(args) < 3 {
			return fmt.Errorf("4eyes deny: usage: 4eyes deny <token>")
		}
		token := args[2]
		if err := DenyRequest(token); err != nil {
			return err
		}
		fmt.Fprintf(hc.Stdout, "%s%s✗%s Denied request: %s\n", ansiBold, ansiRed, ansiReset, token)
		return nil

	// ── pending ────────────────────────────────────────────────────────────
	case "pending":
		pending, err := ListPending()
		if err != nil {
			return err
		}
		if len(pending) == 0 {
			fmt.Fprintf(hc.Stdout, "%sNo pending requests.%s\n", ansiGray, ansiReset)
			return nil
		}
		fmt.Fprintf(hc.Stdout, "%s%-12s  %-10s  %-12s  %-20s  %s%s\n",
			ansiBold, "TOKEN", "REQUESTER", "HOST", "SUBMITTED", "COMMAND", ansiReset)
		fmt.Fprintln(hc.Stdout, strings.Repeat("─", 80))
		now := time.Now()
		for _, p := range pending {
			ts, _ := time.Parse(time.RFC3339, p.Timestamp)
			age := now.Sub(ts).Round(time.Second)
			host := p.Hostname
			if len(host) > 12 {
				host = host[:12]
			}
			cmd := p.Command
			if len(cmd) > 30 {
				cmd = cmd[:27] + "..."
			}
			fmt.Fprintf(hc.Stdout, "%s%-12s%s  %-10s  %-12s  %-20s  %s\n",
				ansiYellow, p.Token, ansiReset,
				p.Requester, host,
				age.String()+" ago",
				cmd)
		}
		return nil

	// ── test ───────────────────────────────────────────────────────────────
	case "test":
		if len(args) < 3 {
			return fmt.Errorf("4eyes test: usage: 4eyes test <command>")
		}
		testCmd := strings.Join(args[2:], " ")
		rule, matched := MatchesFourEyes(testCmd)
		if !matched {
			fmt.Fprintf(hc.Stdout, "%s%s✓%s %q — no 4-eyes rule matches. Would execute immediately.\n",
				ansiBold, ansiGreen, ansiReset, testCmd)
		} else {
			approverStr := "any authorized user"
			if rule.Approver != "" {
				approverStr = rule.Approver
			}
			fmt.Fprintf(hc.Stdout, "%s%s⚠%s %q — %sMATCHED%s rule %q\n",
				ansiBold, ansiYellow, ansiReset, testCmd, ansiBold, ansiReset, rule.Pattern)
			fmt.Fprintf(hc.Stdout, "   Approver : %s\n", approverStr)
			fmt.Fprintf(hc.Stdout, "   TTL      : %ds\n", rule.TTL)
			fmt.Fprintf(hc.Stdout, "   Action   : %sHELD for dual approval%s\n", ansiYellow, ansiReset)
		}
		return nil

	default:
		return fmt.Errorf("4eyes: unknown subcommand %q\nRun: 4eyes --help", args[1])
	}
}

// fourEyesList prints the rules table followed by pending requests.
func fourEyesList(ctx context.Context) error {
	hc := interp.HandlerCtx(ctx)

	rules, err := LoadFourEyesRules()
	if err != nil {
		return err
	}

	// ── Rules table ────────────────────────────────────────────────────────
	fmt.Fprintf(hc.Stdout, "\n%s4-Eyes Rules%s\n", ansiBold+ansiCyan, ansiReset)
	fmt.Fprintln(hc.Stdout, strings.Repeat("─", 60))
	if len(rules) == 0 {
		fmt.Fprintf(hc.Stdout, "%sNo rules configured.%s\n", ansiGray, ansiReset)
	} else {
		fmt.Fprintf(hc.Stdout, "%s%-30s  %-12s  %s%s\n",
			ansiBold, "PATTERN", "APPROVER", "TTL", ansiReset)
		fmt.Fprintln(hc.Stdout, strings.Repeat("─", 60))
		for _, r := range rules {
			approver := r.Approver
			if approver == "" {
				approver = ansiGray + "(any)" + ansiReset
			}
			fmt.Fprintf(hc.Stdout, "%-30s  %-12s  %ds\n", r.Pattern, approver, r.TTL)
		}
	}

	// ── Pending requests ───────────────────────────────────────────────────
	pending, err := ListPending()
	if err != nil {
		return err
	}
	fmt.Fprintf(hc.Stdout, "\n%sPending Requests%s\n", ansiBold+ansiCyan, ansiReset)
	fmt.Fprintln(hc.Stdout, strings.Repeat("─", 60))
	if len(pending) == 0 {
		fmt.Fprintf(hc.Stdout, "%sNone.%s\n\n", ansiGray, ansiReset)
		return nil
	}
	fmt.Fprintf(hc.Stdout, "%s%-12s  %-10s  %s%s\n",
		ansiBold, "TOKEN", "REQUESTER", "COMMAND", ansiReset)
	fmt.Fprintln(hc.Stdout, strings.Repeat("─", 60))
	for _, p := range pending {
		cmd := p.Command
		if len(cmd) > 34 {
			cmd = cmd[:31] + "..."
		}
		fmt.Fprintf(hc.Stdout, "%s%-12s%s  %-10s  %s\n",
			ansiYellow, p.Token, ansiReset, p.Requester, cmd)
		fmt.Fprintf(hc.Stdout, "   %s4eyes approve %s%s  |  %s4eyes deny %s%s\n",
			ansiGreen, p.Token, ansiReset,
			ansiRed, p.Token, ansiReset)
	}
	fmt.Fprintln(hc.Stdout)
	return nil
}

// printFourEyesHelp prints usage information to stdout.
func printFourEyesHelp(ctx context.Context) error {
	hc := interp.HandlerCtx(ctx)
	fmt.Fprintf(hc.Stdout, `%s4eyes%s — 4-eyes dual-approval gate (SOX/PCI-DSS/FedRAMP)

%sUsage:%s
  4eyes add <pattern> [--approver user] [--ttl seconds]
  4eyes remove <pattern>
  4eyes list
  4eyes approve <token>
  4eyes deny <token>
  4eyes pending
  4eyes test <command>

%sExamples:%s
  4eyes add "drop*"              # require approval for any "drop …" command
  4eyes add "rm -rf*" --ttl 120  # 2-minute window
  4eyes list                     # show rules + pending
  4eyes approve abc123def456
  4eyes test "rm -rf /var/data"

%sEnv vars:%s
  ADSSH_4EYES_WEBHOOK  — HTTP endpoint to POST notification payloads
`,
		ansiBold+ansiCyan, ansiReset,
		ansiBold, ansiReset,
		ansiBold, ansiReset,
		ansiBold, ansiReset,
	)
	return nil
}

func init() {
	Register(fourEyesBinary{})
}
