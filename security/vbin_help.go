package security

import (
	"context"
	"fmt"
	"os"
	"strings"

	"adssh/sys"

	"mvdan.cc/sh/v3/interp"
)

// ── ANSI helpers ─────────────────────────────────────────────────────────────

func bold(s string) string      { return ansiBold + s + ansiReset }
func boldCyan(s string) string  { return ansiBoldCyan + s + ansiReset }
func boldWhite(s string) string { return ansiBoldWhite + s + ansiReset }
func header(s string) string    { return ansiBoldUnder + s + ansiReset }

// highlightMatch wraps the first occurrence of query in s with bold ANSI codes.
func highlightMatch(s, query string) string {
	if query == "" {
		return s
	}
	lc := strings.ToLower(s)
	lq := strings.ToLower(query)
	idx := strings.Index(lc, lq)
	if idx < 0 {
		return s
	}
	return s[:idx] + ansiBold + s[idx:idx+len(query)] + ansiReset + s[idx+len(query):]
}

// ── Terminal width ────────────────────────────────────────────────────────────

func termWidth() int {
	_, cols, err := sys.GetTerminalSize(int(os.Stdin.Fd()))
	if err != nil || cols <= 0 {
		return 80
	}
	return cols
}

// ── helpBinary ────────────────────────────────────────────────────────────────

type helpBinary struct{}

func (helpBinary) Name() string        { return "help" }
func (helpBinary) Description() string { return "Built-in help system — topics, search, and examples" }
func (helpBinary) Usage() string {
	return "help [<topic> | search <kw> | list [cat] | categories | examples <topic>]"
}

func (helpBinary) Run(ctx context.Context, args []string) error {
	// Refresh VBIN entries every invocation so dynamic VBINs are always included.
	PopulateVBINHelp()

	hc := interp.HandlerCtx(ctx)
	w := hc.Stdout

	if len(args) < 2 {
		return helpWelcome(w)
	}

	switch strings.ToLower(args[1]) {
	case "search":
		if len(args) < 3 {
			fmt.Fprintln(w, "Usage: help search <keyword>")
			return nil
		}
		return helpSearch(w, args[2])

	case "list":
		cat := ""
		if len(args) >= 3 {
			cat = args[2]
		}
		return helpList(w, cat)

	case "categories":
		return helpCategories(w)

	case "examples":
		if len(args) < 3 {
			fmt.Fprintln(w, "Usage: help examples <topic>")
			return nil
		}
		return helpExamples(w, args[2])

	default:
		return helpTopic(w, args[1])
	}
}

func init() { Register(helpBinary{}) }

// ── Subcommand implementations ────────────────────────────────────────────────

func helpWelcome(w interface{ Write([]byte) (int, error) }) error {
	fmt.Fprintf(w, "%s — programmable security-first shell\n\n", bold("adssh"))

	fmt.Fprintf(w, "%s\n", header("CATEGORIES"))
	cats := HelpCategories()
	for _, c := range cats {
		entries := HelpByCategory(c)
		var names []string
		for _, e := range entries {
			names = append(names, e.Name)
		}
		preview := strings.Join(names, ", ")
		if len(preview) > 60 {
			preview = preview[:57] + "..."
		}
		fmt.Fprintf(w, "  %-10s %s\n", boldCyan(c), preview)
	}

	fmt.Fprintf(w, "\n%s\n", header("QUICK START"))
	examples := []struct{ cmd, desc string }{
		{"help list vbin", "list all virtual binaries"},
		{"help aws", "AWS namespace reference"},
		{"help 4eyes", "dual-approval gate"},
		{"help search <keyword>", "search all topics"},
	}
	for _, ex := range examples {
		fmt.Fprintf(w, "  %-34s %s\n", boldWhite(ex.cmd), ex.desc)
	}

	fmt.Fprintf(w, "\nType any command followed by %s for usage.\n", bold("--help"))
	return nil
}

func helpTopic(w interface{ Write([]byte) (int, error) }, name string) error {
	entry, ok := GetHelp(name)
	if !ok {
		// Try search as fallback
		results := SearchHelp(name)
		if len(results) == 0 {
			fmt.Fprintf(w, "No help found for %q. Try: help search %s\n", name, name)
			return nil
		}
		fmt.Fprintf(w, "No exact match for %q. Did you mean one of these?\n\n", name)
		for _, r := range results {
			if len(results) > 8 {
				break
			}
			fmt.Fprintf(w, "  %-16s [%s]  %s\n", boldWhite(r.Name), boldCyan(r.Category), r.Summary)
		}
		return nil
	}

	width := termWidth()

	// Title line
	title := entry.Name
	if entry.Summary != "" {
		title += " — " + entry.Summary
	}
	fmt.Fprintf(w, "%s\n", bold(title))
	fmt.Fprintf(w, "Category: %s\n", boldCyan(entry.Category))

	if entry.Description != "" {
		fmt.Fprintf(w, "\n%s\n", header("DESCRIPTION"))
		fmt.Fprintf(w, "%s\n", wordWrap(entry.Description, width-2))
	}

	if entry.Usage != "" {
		fmt.Fprintf(w, "\n%s\n", header("USAGE"))
		for _, line := range strings.Split(entry.Usage, "\n") {
			fmt.Fprintf(w, "  %s\n", boldWhite(strings.TrimSpace(line)))
		}
	}

	if len(entry.Examples) > 0 {
		fmt.Fprintf(w, "\n%s\n", header("EXAMPLES"))
		for _, ex := range entry.Examples {
			if ex.Description != "" {
				fmt.Fprintf(w, "  %-42s %s\n", boldWhite(ex.Command), ex.Description)
			} else {
				fmt.Fprintf(w, "  %s\n", boldWhite(ex.Command))
			}
		}
	}

	if len(entry.SeeAlso) > 0 {
		fmt.Fprintf(w, "\n%s\n", header("SEE ALSO"))
		fmt.Fprintf(w, "  %s\n", strings.Join(entry.SeeAlso, ", "))
	}

	return nil
}

func helpSearch(w interface{ Write([]byte) (int, error) }, query string) error {
	results := SearchHelp(query)
	if len(results) == 0 {
		fmt.Fprintf(w, "No results for %q\n", query)
		return nil
	}
	fmt.Fprintf(w, "Search results for %q (%d match", query, len(results))
	if len(results) != 1 {
		fmt.Fprint(w, "es")
	}
	fmt.Fprintln(w, ")")
	fmt.Fprintln(w)
	for _, r := range results {
		name := highlightMatch(r.Name, query)
		summary := highlightMatch(r.Summary, query)
		fmt.Fprintf(w, "  %-18s [%s]  %s\n", boldWhite(name), boldCyan(r.Category), summary)
	}
	return nil
}

func helpList(w interface{ Write([]byte) (int, error) }, cat string) error {
	var entries []HelpEntry
	if cat == "" {
		entries = AllHelpEntries()
	} else {
		entries = HelpByCategory(cat)
		if len(entries) == 0 {
			fmt.Fprintf(w, "No entries for category %q\n", cat)
			return nil
		}
	}

	currentCat := ""
	for _, e := range entries {
		if e.Category != currentCat {
			currentCat = e.Category
			fmt.Fprintf(w, "\n%s\n", header(strings.ToUpper(currentCat)))
		}
		fmt.Fprintf(w, "  %-18s %s\n", boldWhite(e.Name), e.Summary)
	}
	return nil
}

func helpCategories(w interface{ Write([]byte) (int, error) }) error {
	fmt.Fprintln(w, "Available categories:")
	fmt.Fprintln(w)
	for _, cat := range HelpCategories() {
		entries := HelpByCategory(cat)
		fmt.Fprintf(w, "  %-12s %d topic(s)\n", boldCyan(cat), len(entries))
	}
	return nil
}

func helpExamples(w interface{ Write([]byte) (int, error) }, name string) error {
	entry, ok := GetHelp(name)
	if !ok {
		fmt.Fprintf(w, "No help found for %q\n", name)
		return nil
	}
	if len(entry.Examples) == 0 {
		fmt.Fprintf(w, "No examples for %q\n", name)
		return nil
	}
	fmt.Fprintf(w, "%s\n\n", bold(entry.Name+" — examples"))
	for _, ex := range entry.Examples {
		fmt.Fprintf(w, "  %s\n", boldWhite(ex.Command))
		if ex.Description != "" {
			fmt.Fprintf(w, "    %s\n", ex.Description)
		}
		fmt.Fprintln(w)
	}
	return nil
}
