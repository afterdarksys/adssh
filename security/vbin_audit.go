package security

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"mvdan.cc/sh/v3/interp"
)

// ANSI colour helpers
const (
	ansiReset     = "\033[0m"
	ansiRed       = "\033[31m"
	ansiGreen     = "\033[32m"
	ansiYellow    = "\033[33m"
	ansiCyan      = "\033[36m"
	ansiBold      = "\033[1m"
	ansiUnderline = "\033[4m"
	ansiBoldCyan  = "\033[1;36m"
	ansiBoldWhite = "\033[1;37m"
	ansiBoldUnder = "\033[1;4m"
)

// wrapAt wraps a string at maxLen characters, inserting "\n  " for continuation lines.
func wrapAt(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	var sb strings.Builder
	for len(s) > maxLen {
		sb.WriteString(s[:maxLen])
		sb.WriteString("\n  ")
		s = s[maxLen:]
	}
	sb.WriteString(s)
	return sb.String()
}

// colourForEntry returns an ANSI colour for a chain entry based on type/allowed.
func colourForEntry(e ChainEntry) string {
	switch e.Type {
	case "policy":
		if e.Allowed != nil && !*e.Allowed {
			return ansiRed
		}
		return ansiGreen
	case "event":
		return ansiYellow
	case "cm":
		return ansiCyan
	default:
		return ""
	}
}

// auditBinary implements the 'audit' virtual binary.
type auditBinary struct{}

func (auditBinary) Name() string        { return "audit" }
func (auditBinary) Description() string { return "View, verify, search, and export the HMAC-chain audit ledger" }
func (auditBinary) Usage() string {
	return `audit <subcommand> [options]

Subcommands:
  verify                          Verify chain integrity (PASS/FAIL)
  tail [-n N]                     Tail last N entries (default 20)
  search <keyword>                Case-insensitive search
  export [--format json|csv] [--since YYYY-MM-DD] [--until YYYY-MM-DD]
  stats                           Summary statistics`
}

func (auditBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)

	if len(args) < 2 {
		fmt.Fprintf(hc.Stdout, "Usage: %s\n", auditBinary{}.Usage())
		return nil
	}

	ledger := chainLedgerPath()

	switch args[1] {
	case "verify":
		return auditVerify(ctx, hc, ledger)
	case "tail":
		n := 20
		for i := 2; i < len(args); i++ {
			if args[i] == "-n" && i+1 < len(args) {
				if v, err := strconv.Atoi(args[i+1]); err == nil && v > 0 {
					n = v
				}
				i++
			}
		}
		return auditTail(ctx, hc, ledger, n)
	case "search":
		if len(args) < 3 {
			return fmt.Errorf("audit search: missing keyword")
		}
		keyword := strings.Join(args[2:], " ")
		return auditSearch(ctx, hc, ledger, keyword)
	case "export":
		format := "json"
		since := ""
		until := ""
		for i := 2; i < len(args); i++ {
			switch args[i] {
			case "--format":
				if i+1 < len(args) {
					format = args[i+1]
					i++
				}
			case "--since":
				if i+1 < len(args) {
					since = args[i+1]
					i++
				}
			case "--until":
				if i+1 < len(args) {
					until = args[i+1]
					i++
				}
			}
		}
		return auditExport(ctx, hc, ledger, format, since, until)
	case "stats":
		return auditStats(ctx, hc, ledger)
	default:
		fmt.Fprintf(hc.Stderr, "audit: unknown subcommand %q\n", args[1])
		fmt.Fprintf(hc.Stdout, "Usage: %s\n", auditBinary{}.Usage())
		return nil
	}
}

// chainLedgerPath returns the current ledger path.
func chainLedgerPath() string {
	chainMu.Lock()
	defer chainMu.Unlock()
	return chainPath
}

func auditVerify(_ context.Context, hc interp.HandlerContext, ledger string) error {
	if ledger == "" {
		fmt.Fprintf(hc.Stderr, "audit verify: chain not initialised\n")
		return nil
	}
	ok, badSeq, err := VerifyChain(ledger)
	if err != nil {
		fmt.Fprintf(hc.Stderr, "%sERROR%s verifying chain: %v\n", ansiRed, ansiReset, err)
		return nil
	}
	if ok {
		fmt.Fprintf(hc.Stdout, "%s%sPASS%s — chain integrity verified\n", ansiBold, ansiGreen, ansiReset)
	} else {
		fmt.Fprintf(hc.Stdout, "%s%sFAIL%s — broken link at seq %d\n", ansiBold, ansiRed, ansiReset, badSeq)
	}
	return nil
}

func auditTail(_ context.Context, hc interp.HandlerContext, ledger string, n int) error {
	if ledger == "" {
		fmt.Fprintf(hc.Stderr, "audit tail: chain not initialised\n")
		return nil
	}

	entries, err := readAllChainEntries(ledger)
	if err != nil {
		fmt.Fprintf(hc.Stderr, "audit tail: %v\n", err)
		return nil
	}

	start := 0
	if len(entries) > n {
		start = len(entries) - n
	}

	// Header
	fmt.Fprintf(hc.Stdout, "%s%s%-6s %-24s %-10s %-8s %s%s\n",
		ansiBold, ansiCyan,
		"SEQ", "TIMESTAMP", "USER", "TYPE", "COMMAND",
		ansiReset)
	fmt.Fprintf(hc.Stdout, "%s%s\n", ansiCyan, strings.Repeat("─", 80)+ansiReset)

	for _, e := range entries[start:] {
		colour := colourForEntry(e)
		ts := e.Timestamp
		if len(ts) > 23 {
			ts = ts[:23]
		}
		cmd := wrapAt(e.Command, 60)
		if cmd == "" {
			cmd = e.Source
		}
		fmt.Fprintf(hc.Stdout, "%s%-6d %-24s %-10s %-8s %s%s\n",
			colour,
			e.Seq,
			ts,
			truncate(e.User, 10),
			e.Type,
			cmd,
			ansiReset)
	}
	return nil
}

func auditSearch(_ context.Context, hc interp.HandlerContext, ledger, keyword string) error {
	if ledger == "" {
		fmt.Fprintf(hc.Stderr, "audit search: chain not initialised\n")
		return nil
	}

	f, err := os.Open(ledger)
	if err != nil {
		fmt.Fprintf(hc.Stderr, "audit search: %v\n", err)
		return nil
	}
	defer f.Close()

	lower := strings.ToLower(keyword)
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.Contains(strings.ToLower(line), lower) {
			continue
		}
		var e ChainEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		colour := colourForEntry(e)
		ts := e.Timestamp
		if len(ts) > 23 {
			ts = ts[:23]
		}
		cmd := e.Command
		if cmd == "" {
			cmd = e.Source
		}
		fmt.Fprintf(hc.Stdout, "%s[%d] %s  %-8s  %s  %-10s  %s%s\n",
			colour,
			e.Seq,
			ts,
			e.Type,
			truncate(e.User, 10),
			truncate(e.SessionID, 10),
			wrapAt(cmd, 60),
			ansiReset)
		count++
	}
	if count == 0 {
		fmt.Fprintf(hc.Stdout, "(no matches for %q)\n", keyword)
	} else {
		fmt.Fprintf(hc.Stdout, "\n%d match(es) found\n", count)
	}
	return nil
}

func auditExport(_ context.Context, hc interp.HandlerContext, ledger, format, since, until string) error {
	if ledger == "" {
		fmt.Fprintf(hc.Stderr, "audit export: chain not initialised\n")
		return nil
	}
	data, err := ExportChain(ledger, format, since, until)
	if err != nil {
		fmt.Fprintf(hc.Stderr, "audit export: %v\n", err)
		return nil
	}
	hc.Stdout.Write(data)
	fmt.Fprintln(hc.Stdout)
	return nil
}

func auditStats(_ context.Context, hc interp.HandlerContext, ledger string) error {
	if ledger == "" {
		fmt.Fprintf(hc.Stderr, "audit stats: chain not initialised\n")
		return nil
	}

	entries, err := readAllChainEntries(ledger)
	if err != nil {
		fmt.Fprintf(hc.Stderr, "audit stats: %v\n", err)
		return nil
	}

	if len(entries) == 0 {
		fmt.Fprintf(hc.Stdout, "audit: ledger is empty\n")
		return nil
	}

	sessions := map[string]struct{}{}
	users := map[string]struct{}{}
	var earliest, latest time.Time

	for _, e := range entries {
		sessions[e.SessionID] = struct{}{}
		users[e.User] = struct{}{}
		ts, err := time.Parse(time.RFC3339Nano, e.Timestamp)
		if err != nil {
			ts, _ = time.Parse(time.RFC3339, e.Timestamp)
		}
		if earliest.IsZero() || ts.Before(earliest) {
			earliest = ts
		}
		if ts.After(latest) {
			latest = ts
		}
	}

	// Verify chain
	verifyStatus := ansiGreen + "PASS" + ansiReset
	ok, badSeq, verifyErr := VerifyChain(ledger)
	if verifyErr != nil || !ok {
		if verifyErr != nil {
			verifyStatus = fmt.Sprintf("%sFAIL%s (%v)", ansiRed, ansiReset, verifyErr)
		} else {
			verifyStatus = fmt.Sprintf("%sFAIL%s (broken at seq %d)", ansiRed, ansiReset, badSeq)
		}
	}

	fmt.Fprintf(hc.Stdout, "%s%sAudit Chain Statistics%s\n", ansiBold, ansiCyan, ansiReset)
	fmt.Fprintf(hc.Stdout, "%s%s\n", ansiCyan, strings.Repeat("─", 40)+ansiReset)
	fmt.Fprintf(hc.Stdout, "  Total entries : %d\n", len(entries))
	fmt.Fprintf(hc.Stdout, "  Sessions      : %d\n", len(sessions))
	fmt.Fprintf(hc.Stdout, "  Unique users  : %d\n", len(users))
	if !earliest.IsZero() {
		fmt.Fprintf(hc.Stdout, "  Earliest      : %s\n", earliest.Format(time.RFC3339))
		fmt.Fprintf(hc.Stdout, "  Latest        : %s\n", latest.Format(time.RFC3339))
	}
	fmt.Fprintf(hc.Stdout, "  Chain status  : %s\n", verifyStatus)
	fmt.Fprintf(hc.Stdout, "  Ledger path   : %s\n", ledger)
	return nil
}

// readAllChainEntries reads all chain entries from the ledger.
func readAllChainEntries(ledger string) ([]ChainEntry, error) {
	f, err := os.Open(ledger)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var entries []ChainEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e ChainEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	return entries, scanner.Err()
}

// truncate shortens a string to at most n characters.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func init() {
	Register(auditBinary{})
}
