package security

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/interp"
)

// historyBinary implements the history virtual binary.
//
// Supported operations:
//
//	history       — print all history entries numbered from 1
//	history N     — print last N entries
//	history -c    — clear history file (truncate to empty)
//	history -d N  — delete entry N from history file
type historyBinary struct{}

func (historyBinary) Name() string        { return "history" }
func (historyBinary) Description() string { return "Display or manipulate the command history list" }
func (historyBinary) Usage() string {
	return "history [N | -c | -d N]"
}

func (historyBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	histFile := historyFilePath()

	lines, err := readHistoryLines(histFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("history: %v", err)
	}

	if len(args) < 2 {
		// Print all entries
		printHistoryEntries(hc.Stdout, lines, 0)
		return nil
	}

	switch args[1] {
	case "-c":
		// Clear history file
		if err := os.WriteFile(histFile, []byte{}, 0600); err != nil {
			return fmt.Errorf("history -c: %v", err)
		}
		return nil

	case "-d":
		if len(args) < 3 {
			return fmt.Errorf("history -d: missing entry number")
		}
		n, err := strconv.Atoi(args[2])
		if err != nil || n < 1 || n > len(lines) {
			return fmt.Errorf("history -d: invalid entry %q", args[2])
		}
		// Remove line n (1-indexed)
		newLines := make([]string, 0, len(lines)-1)
		newLines = append(newLines, lines[:n-1]...)
		newLines = append(newLines, lines[n:]...)
		if err := writeHistoryLines(histFile, newLines); err != nil {
			return fmt.Errorf("history -d: %v", err)
		}
		return nil

	default:
		// history N — print last N entries
		n, err := strconv.Atoi(args[1])
		if err != nil || n < 0 {
			return fmt.Errorf("history: invalid argument %q\nUsage: %s", args[1], historyBinary{}.Usage())
		}
		printHistoryEntries(hc.Stdout, lines, n)
		return nil
	}
}

// historyFilePath returns the path to the readline history file.
// It checks ADSSH_HISTORY_FILE first, then falls back to ~/.adssh/history.
func historyFilePath() string {
	if p := os.Getenv("ADSSH_HISTORY_FILE"); p != "" {
		return p
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ".adssh/history"
	}
	return filepath.Join(homeDir, ".adssh", "history")
}

// readHistoryLines reads all lines from the history file.
func readHistoryLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// writeHistoryLines rewrites the history file with the given lines.
func writeHistoryLines(path string, lines []string) error {
	var sb strings.Builder
	for _, l := range lines {
		sb.WriteString(l)
		sb.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(sb.String()), 0600)
}

// printHistoryEntries prints history entries numbered from 1.
// If last > 0, only the last N entries are printed.
func printHistoryEntries(w interface{ Write([]byte) (int, error) }, lines []string, last int) {
	start := 0
	if last > 0 && last < len(lines) {
		start = len(lines) - last
	}
	for i := start; i < len(lines); i++ {
		fmt.Fprintf(w, "%5d  %s\n", i+1, lines[i])
	}
}

// ────────────────────────────────────────────────────────────────────────────
// fcBinary implements the fc virtual binary.
//
// Supported operations:
//
//	fc            — open last command in $EDITOR, save, print for re-execution
//	fc -l         — list recent history (same as history)
//	fc -l N       — list last N history entries
//	fc -l M N     — list entries M through N
//	fc N          — print history entry N for re-execution
//	fc old new    — re-execute last command with old→new substitution
type fcBinary struct{}

func (fcBinary) Name() string        { return "fc" }
func (fcBinary) Description() string { return "List or edit and re-execute history commands" }
func (fcBinary) Usage() string {
	return "fc [-l [M [N]] | -e editor | N | old new]"
}

func (fcBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	histFile := historyFilePath()

	lines, err := readHistoryLines(histFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("fc: %v", err)
	}

	// fc with no arguments — open last command in $EDITOR
	if len(args) < 2 {
		return fcEditAndPrint(ctx, hc, lines)
	}

	switch args[1] {
	case "-l":
		// fc -l [M [N]]
		switch len(args) {
		case 2:
			// fc -l — list all (same as history)
			printHistoryEntries(hc.Stdout, lines, 0)
		case 3:
			// fc -l N — list last N entries
			n, err := strconv.Atoi(args[2])
			if err != nil || n < 0 {
				return fmt.Errorf("fc -l: invalid count %q", args[2])
			}
			printHistoryEntries(hc.Stdout, lines, n)
		default:
			// fc -l M N — list entries M through N (1-indexed)
			m, err1 := strconv.Atoi(args[2])
			n, err2 := strconv.Atoi(args[3])
			if err1 != nil || err2 != nil || m < 1 || n < m || n > len(lines) {
				return fmt.Errorf("fc -l: invalid range %q %q", args[2], args[3])
			}
			for i := m - 1; i < n && i < len(lines); i++ {
				fmt.Fprintf(hc.Stdout, "%5d  %s\n", i+1, lines[i])
			}
		}
		return nil

	case "-e":
		// fc -e editor [N] — open entry N (or last) in specified editor
		editor := ""
		entryIdx := len(lines) - 1
		if len(args) >= 3 {
			editor = args[2]
		}
		if len(args) >= 4 {
			n, err := strconv.Atoi(args[3])
			if err != nil || n < 1 || n > len(lines) {
				return fmt.Errorf("fc -e: invalid entry %q", args[3])
			}
			entryIdx = n - 1
		}
		if entryIdx < 0 || len(lines) == 0 {
			return fmt.Errorf("fc: no history")
		}
		return fcEditEntryAndPrint(ctx, hc, lines[entryIdx], editor)

	default:
		// Could be: fc N  or  fc old new
		if len(args) == 2 {
			// fc N — print history entry N for re-execution
			n, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("fc: invalid argument %q\nUsage: %s", args[1], fcBinary{}.Usage())
			}
			if n < 1 || n > len(lines) {
				return fmt.Errorf("fc: %d: history entry not found", n)
			}
			cmd := lines[n-1]
			fmt.Fprintf(hc.Stdout, "# would re-execute (paste to run):\n%s\n", cmd)
			return nil
		}

		if len(args) == 3 {
			// fc old new — substitute in last command and print
			if len(lines) == 0 {
				return fmt.Errorf("fc: no history")
			}
			last := lines[len(lines)-1]
			oldStr := args[1]
			newStr := args[2]
			if !strings.Contains(last, oldStr) {
				return fmt.Errorf("fc: substitution failed: %q not found in last command", oldStr)
			}
			substituted := strings.Replace(last, oldStr, newStr, 1)
			fmt.Fprintf(hc.Stdout, "# would re-execute (paste to run):\n%s\n", substituted)
			return nil
		}

		return fmt.Errorf("fc: too many arguments\nUsage: %s", fcBinary{}.Usage())
	}
}

// fcEditAndPrint writes the last command to a temp file, opens it in $EDITOR,
// waits for the editor to exit, then prints the (possibly modified) command.
func fcEditAndPrint(ctx context.Context, hc interp.HandlerContext, lines []string) error {
	if len(lines) == 0 {
		return fmt.Errorf("fc: no history")
	}
	return fcEditEntryAndPrint(ctx, hc, lines[len(lines)-1], "")
}

// fcEditEntryAndPrint opens cmd in the editor and prints the result.
func fcEditEntryAndPrint(_ context.Context, hc interp.HandlerContext, cmd string, editorOverride string) error {
	editor := editorOverride
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		editor = "vi"
	}

	// Write the command to a temporary file
	tmpFile, err := os.CreateTemp("", "adssh-fc-*.sh")
	if err != nil {
		return fmt.Errorf("fc: create temp file: %v", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.WriteString(cmd + "\n"); err != nil {
		tmpFile.Close()
		return fmt.Errorf("fc: write temp file: %v", err)
	}
	tmpFile.Close()

	// Open in editor
	editorCmd := exec.Command(editor, tmpPath)
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr
	if err := editorCmd.Run(); err != nil {
		return fmt.Errorf("fc: editor %q: %v", editor, err)
	}

	// Read back the (possibly modified) command
	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return fmt.Errorf("fc: read temp file: %v", err)
	}
	result := strings.TrimRight(string(data), "\n")
	fmt.Fprintf(hc.Stdout, "# would re-execute (paste to run):\n%s\n", result)
	return nil
}

func init() {
	Register(historyBinary{})
	Register(fcBinary{})
}
