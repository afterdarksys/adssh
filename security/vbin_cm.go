package security

import (
	"context"
	"fmt"
	"os"
	"strings"

	"mvdan.cc/sh/v3/interp"
)

// cmBinary implements the "cm" virtual binary for change-management operations.
type cmBinary struct{}

func (cmBinary) Name() string { return "cm" }
func (cmBinary) Description() string {
	return "Change management — associate session with an approved change ticket"
}
func (cmBinary) Usage() string {
	return "cm <set|check|clear|status|require|providers> [args]"
}

func (cmBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)

	if len(args) < 2 {
		fmt.Fprintf(hc.Stdout, "Usage: %s\n", cmBinary{}.Usage())
		fmt.Fprintln(hc.Stdout, "\nSubcommands:")
		fmt.Fprintln(hc.Stdout, "  set <ticket-id>   Fetch and activate a change ticket")
		fmt.Fprintln(hc.Stdout, "  check [ticket-id] Check ticket status (active ticket if no ID given)")
		fmt.Fprintln(hc.Stdout, "  clear             Clear the active change ticket")
		fmt.Fprintln(hc.Stdout, "  status            Show active ticket summary")
		fmt.Fprintln(hc.Stdout, "  require <pattern> Append a command pattern to ADSSH_CM_PATTERNS")
		fmt.Fprintln(hc.Stdout, "  providers         Show configured provider information")
		return nil
	}

	switch args[1] {
	case "set":
		return cmSet(ctx, hc, args)
	case "check":
		return cmCheck(ctx, hc, args)
	case "clear":
		return cmClear(ctx, hc)
	case "status":
		return cmStatus(ctx, hc)
	case "require":
		return cmRequire(ctx, hc, args)
	case "providers":
		return cmProviders(ctx, hc)
	default:
		return fmt.Errorf("cm: unknown subcommand %q\nUsage: %s", args[1], cmBinary{}.Usage())
	}
}

// cmSet fetches the ticket by ID, validates it, and stores it as active.
func cmSet(_ context.Context, hc interp.HandlerContext, args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("cm set: missing ticket-id\nUsage: cm set <ticket-id>")
	}
	id := args[2]

	ticket, err := FetchCMTicket(id)
	if err != nil {
		fmt.Fprintf(hc.Stdout, "%s✗%s %v\n", ansiRed, ansiReset, err)
		return err
	}

	if !IsTicketValid(ticket) {
		fmt.Fprintf(hc.Stdout, "%s✗%s Change ticket %s is not approved (state: %s)\n",
			ansiRed, ansiReset, ticket.ID, ticket.State)
		return fmt.Errorf("cm: ticket %s is not valid for use (state: %s)", ticket.ID, ticket.State)
	}

	SetActiveCMTicket(ticket, id)

	stateColour := ansiGreen
	stateSymbol := "✓"
	if ticket.State != "approved" {
		stateColour = ansiYellow
		stateSymbol = "⚠"
	}

	fmt.Fprintf(hc.Stdout, "%s%s%s Change ticket %s\n", stateColour, stateSymbol, ansiReset, ticket.ID)
	fmt.Fprintf(hc.Stdout, "  Title:    %s\n", ticket.Title)
	fmt.Fprintf(hc.Stdout, "  State:    %s\n", ticket.State)
	fmt.Fprintf(hc.Stdout, "  Assignee: %s\n", ticket.Assignee)

	if !ticket.StartWindow.IsZero() || !ticket.EndWindow.IsZero() {
		start := "—"
		end := "—"
		if !ticket.StartWindow.IsZero() {
			start = ticket.StartWindow.Format("2006-01-02 15:04")
		}
		if !ticket.EndWindow.IsZero() {
			end = ticket.EndWindow.Format("2006-01-02 15:04")
		}
		fmt.Fprintf(hc.Stdout, "  Window:   %s → %s\n", start, end)
	}

	fmt.Fprintln(hc.Stdout, "")
	fmt.Fprintln(hc.Stdout, "Session audit log will include ticket ID in all entries.")
	return nil
}

// cmCheck checks the status of a ticket (by ID or active).
func cmCheck(_ context.Context, hc interp.HandlerContext, args []string) error {
	var id string
	var ticket *CMTicket

	if len(args) >= 3 {
		id = args[2]
		var err error
		ticket, err = FetchCMTicket(id)
		if err != nil {
			fmt.Fprintf(hc.Stdout, "%s✗%s %v\n", ansiRed, ansiReset, err)
			return err
		}
	} else {
		var activeID string
		ticket, activeID = GetActiveCMTicket()
		if ticket == nil {
			fmt.Fprintf(hc.Stdout, "%s⚠%s No active change ticket set.\n", ansiYellow, ansiReset)
			fmt.Fprintln(hc.Stdout, "Run: cm set <ticket-id>")
			return nil
		}
		id = activeID
	}

	valid := IsTicketValid(ticket)
	symbol := ansiGreen + "✓" + ansiReset
	if !valid {
		if ticket.State == "closed" {
			symbol = ansiRed + "✗" + ansiReset
		} else {
			symbol = ansiYellow + "⚠" + ansiReset
		}
	}

	fmt.Fprintf(hc.Stdout, "%s Ticket %s\n", symbol, id)
	fmt.Fprintf(hc.Stdout, "  State:    %s\n", ticket.State)
	fmt.Fprintf(hc.Stdout, "  Assignee: %s\n", ticket.Assignee)

	if !ticket.StartWindow.IsZero() || !ticket.EndWindow.IsZero() {
		start := "—"
		end := "—"
		if !ticket.StartWindow.IsZero() {
			start = ticket.StartWindow.Format("2006-01-02 15:04")
		}
		if !ticket.EndWindow.IsZero() {
			end = ticket.EndWindow.Format("2006-01-02 15:04")
		}
		fmt.Fprintf(hc.Stdout, "  Window:   %s → %s\n", start, end)
	}
	return nil
}

// cmClear removes the active CM ticket from the session.
func cmClear(_ context.Context, hc interp.HandlerContext) error {
	_, id := GetActiveCMTicket()
	ClearActiveCMTicket()
	if id != "" {
		fmt.Fprintf(hc.Stdout, "%s✓%s Cleared active ticket %s\n", ansiGreen, ansiReset, id)
	} else {
		fmt.Fprintf(hc.Stdout, "%s⚠%s No active ticket was set.\n", ansiYellow, ansiReset)
	}
	return nil
}

// cmStatus prints the currently active ticket, or "no ticket set".
func cmStatus(_ context.Context, hc interp.HandlerContext) error {
	ticket, id := GetActiveCMTicket()
	if ticket == nil {
		fmt.Fprintf(hc.Stdout, "%s⚠%s No change ticket set.\n", ansiYellow, ansiReset)
		fmt.Fprintln(hc.Stdout, "Run: cm set <ticket-id>")
		return nil
	}

	valid := IsTicketValid(ticket)
	symbol := ansiGreen + "✓" + ansiReset
	if !valid {
		symbol = ansiYellow + "⚠" + ansiReset
	}

	fmt.Fprintf(hc.Stdout, "%s Active ticket: %s\n", symbol, id)
	fmt.Fprintf(hc.Stdout, "  Title:    %s\n", ticket.Title)
	fmt.Fprintf(hc.Stdout, "  State:    %s\n", ticket.State)
	fmt.Fprintf(hc.Stdout, "  Assignee: %s\n", ticket.Assignee)
	fmt.Fprintf(hc.Stdout, "  Provider: %s\n", ticket.Provider)

	if !ticket.StartWindow.IsZero() || !ticket.EndWindow.IsZero() {
		start := "—"
		end := "—"
		if !ticket.StartWindow.IsZero() {
			start = ticket.StartWindow.Format("2006-01-02 15:04")
		}
		if !ticket.EndWindow.IsZero() {
			end = ticket.EndWindow.Format("2006-01-02 15:04")
		}
		fmt.Fprintf(hc.Stdout, "  Window:   %s → %s\n", start, end)
	}
	return nil
}

// cmRequire appends a command pattern to ADSSH_CM_PATTERNS.
func cmRequire(_ context.Context, hc interp.HandlerContext, args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("cm require: missing pattern\nUsage: cm require <glob-pattern>")
	}
	pattern := args[2]

	existing := os.Getenv("ADSSH_CM_PATTERNS")
	var updated string
	if existing == "" {
		updated = pattern
	} else {
		// avoid duplicates
		for _, p := range strings.Split(existing, ",") {
			if strings.TrimSpace(p) == pattern {
				fmt.Fprintf(hc.Stdout, "%s⚠%s Pattern %q already present in ADSSH_CM_PATTERNS.\n",
					ansiYellow, ansiReset, pattern)
				return nil
			}
		}
		updated = existing + "," + pattern
	}

	if err := os.Setenv("ADSSH_CM_PATTERNS", updated); err != nil {
		return fmt.Errorf("cm require: setenv: %w", err)
	}
	fmt.Fprintf(hc.Stdout, "%s✓%s Added %q to ADSSH_CM_PATTERNS\n", ansiGreen, ansiReset, pattern)
	fmt.Fprintf(hc.Stdout, "  ADSSH_CM_PATTERNS=%s\n", updated)
	return nil
}

// cmProviders lists the configured CM provider and its status.
func cmProviders(_ context.Context, hc interp.HandlerContext) error {
	provider := os.Getenv("ADSSH_CM_PROVIDER")
	if provider == "" {
		provider = "generic (default)"
	}
	url := os.Getenv("ADSSH_CM_URL")
	tokenSet := os.Getenv("ADSSH_CM_TOKEN") != ""
	strictMode := CMStrictMode()
	patterns := os.Getenv("ADSSH_CM_PATTERNS")

	urlStatus := ansiGreen + "✓" + ansiReset
	if url == "" {
		url = "(not set)"
		urlStatus = ansiRed + "✗" + ansiReset
	}
	tokenStatus := ansiYellow + "⚠ not set" + ansiReset
	if tokenSet {
		tokenStatus = ansiGreen + "✓ configured" + ansiReset
	}
	strictStatus := "off"
	if strictMode {
		strictStatus = ansiYellow + "on" + ansiReset
	}

	fmt.Fprintln(hc.Stdout, "Change Management Provider Configuration:")
	fmt.Fprintf(hc.Stdout, "  Provider:    %s\n", provider)
	fmt.Fprintf(hc.Stdout, "  URL:         %s %s\n", urlStatus, url)
	fmt.Fprintf(hc.Stdout, "  Token:       %s\n", tokenStatus)
	fmt.Fprintf(hc.Stdout, "  Strict mode: %s\n", strictStatus)
	if patterns == "" {
		fmt.Fprintf(hc.Stdout, "  Patterns:    (none — use 'cm require <pattern>' to add)\n")
	} else {
		fmt.Fprintf(hc.Stdout, "  Patterns:    %s\n", patterns)
	}
	return nil
}

func init() { Register(cmBinary{}) }
