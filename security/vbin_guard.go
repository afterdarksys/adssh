package security

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/afterdarksys/adssh/internal/guard"
	"mvdan.cc/sh/v3/interp"
)

// guardBinary is the operator interface to the SSH listener jail.
type guardBinary struct{}

func (guardBinary) Name() string { return "guard" }

func (guardBinary) Description() string {
	return "Show and manage the SSH listener ban table"
}

func (guardBinary) Usage() string {
	return `guard <subcommand> [--json]

Subcommands:
  status                 Effective config and active bans
  config                 Effective config
  list                   Active bans
  unban <ip>             Remove one ban and its strikes
  reload                 Reread guard.yaml and the ban file

--json may appear anywhere after the command name.`
}

func init() { Register(guardBinary{}) }

func (guardBinary) Run(ctx context.Context, args []string) error {
	jsonOut := false
	rest := make([]string, 0, len(args))
	for _, arg := range args[1:] {
		if arg == "--json" {
			jsonOut = true
			continue
		}
		rest = append(rest, arg)
	}
	if len(rest) == 0 {
		return fmt.Errorf("guard: missing subcommand")
	}
	out := guardStdout(ctx)
	switch rest[0] {
	case "status", "config", "list", "reload":
		if len(rest) != 1 {
			return fmt.Errorf("guard %s: unexpected arguments", rest[0])
		}
	case "unban":
		if len(rest) != 2 || strings.TrimSpace(rest[1]) == "" {
			return fmt.Errorf("guard unban: address required")
		}
	default:
		return fmt.Errorf("guard: unknown subcommand %q", rest[0])
	}

	switch rest[0] {
	case "status":
		st := guard.Status()
		if jsonOut {
			return writeGuardJSON(out, st)
		}
		writeGuardConfig(out, st)
		writeGuardBans(out, st.Bans)
		return nil
	case "config":
		st := guard.Status()
		if jsonOut {
			return writeGuardJSON(out, guardConfigView(st))
		}
		writeGuardConfig(out, st)
		return nil
	case "list":
		bans := guard.Status().Bans
		if jsonOut {
			return writeGuardJSON(out, bans)
		}
		writeGuardBans(out, bans)
		return nil
	case "unban":
		key, err := guard.Unban(rest[1])
		if err != nil {
			return err
		}
		if jsonOut {
			return writeGuardJSON(out, map[string]any{"ok": true, "addr": key})
		}
		fmt.Fprintf(out, "unbanned %s\n", key)
		return nil
	case "reload":
		if err := guard.Reload(); err != nil {
			return err
		}
		if jsonOut {
			return writeGuardJSON(out, map[string]any{"ok": true})
		}
		fmt.Fprintln(out, "reloaded")
		return nil
	default:
		return fmt.Errorf("guard: unknown subcommand %q", rest[0])
	}
}

func guardStdout(ctx context.Context) io.Writer {
	hc := interp.HandlerCtx(ctx)
	if hc.Stdout == nil {
		return io.Discard
	}
	return hc.Stdout
}

func writeGuardJSON(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(value)
}

type guardConfigJSON struct {
	Configured bool     `json:"configured"`
	Note       string   `json:"note,omitempty"`
	Enabled    bool     `json:"enabled"`
	ForcedOff  bool     `json:"forced_off"`
	Tripped    string   `json:"tripped,omitempty"`
	ConfigPath string   `json:"config_path"`
	StatePath  string   `json:"state_path"`
	FindTime   string   `json:"find_time"`
	MaxRetry   int      `json:"max_retry"`
	BanTime    string   `json:"ban_time"`
	RateLimit  int      `json:"rate_limit"`
	RateWindow string   `json:"rate_window"`
	MaxEntries int      `json:"max_entries"`
	TableFull  string   `json:"table_full"`
	IPv6Prefix int      `json:"ipv6_prefix"`
	Ignore     []string `json:"ignore"`
}

func guardConfigView(st guard.Snapshot) guardConfigJSON {
	return guardConfigJSON{
		Configured: st.Configured,
		Note:       st.Note,
		Enabled:    st.Enabled,
		ForcedOff:  st.ForcedOff,
		Tripped:    st.Tripped,
		ConfigPath: st.ConfigPath,
		StatePath:  st.StatePath,
		FindTime:   st.FindTime,
		MaxRetry:   st.MaxRetry,
		BanTime:    st.BanTime,
		RateLimit:  st.RateLimit,
		RateWindow: st.RateWindow,
		MaxEntries: st.MaxEntries,
		TableFull:  st.TableFull,
		IPv6Prefix: st.IPv6Prefix,
		Ignore:     st.Ignore,
	}
}

func writeGuardConfig(w io.Writer, st guard.Snapshot) {
	if st.Note != "" {
		fmt.Fprintf(w, "note: %s\n", st.Note)
	}
	fmt.Fprintf(w, "enabled: %t\n", st.Enabled)
	fmt.Fprintf(w, "forced_off: %t\n", st.ForcedOff)
	if st.Tripped != "" {
		fmt.Fprintf(w, "tripped: %s\n", st.Tripped)
	}
	fmt.Fprintf(w, "config_path: %s\n", st.ConfigPath)
	fmt.Fprintf(w, "state_path: %s\n", st.StatePath)
	fmt.Fprintf(w, "find_time: %s\n", st.FindTime)
	fmt.Fprintf(w, "max_retry: %d\n", st.MaxRetry)
	fmt.Fprintf(w, "ban_time: %s\n", st.BanTime)
	fmt.Fprintf(w, "rate_limit: %d\n", st.RateLimit)
	fmt.Fprintf(w, "rate_window: %s\n", st.RateWindow)
	fmt.Fprintf(w, "max_entries: %d\n", st.MaxEntries)
	fmt.Fprintf(w, "table_full: %s\n", st.TableFull)
	fmt.Fprintf(w, "ipv6_prefix: %d\n", st.IPv6Prefix)
	fmt.Fprintf(w, "ignore: %s\n", strings.Join(st.Ignore, ", "))
}

func writeGuardBans(w io.Writer, bans []guard.Ban) {
	if len(bans) == 0 {
		fmt.Fprintln(w, "bans: none")
		return
	}
	fmt.Fprintln(w, "bans:")
	for _, ban := range bans {
		fmt.Fprintf(w, "  %s until=%s reason=%s\n", ban.Addr, ban.Until.UTC().Format(time.RFC3339), ban.Reason)
	}
}
