package config

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// Operational logging for the listener processes (SSH server, admin API).
//
//	ADSSH_LOG_LEVEL=error|warn|info|debug   default info
//	ADSSH_LOG_FORMAT=text|json              default text
//
// Logs go to stderr, which journald collects under systemd. They describe
// what the server did (connections, auth attempts, channel requests, session
// start and exit) and are separate from the audit log and hash chain, which
// record what users did. An unknown value refuses startup rather than
// silently logging at some other level.

// LogSettings is a parsed ADSSH_LOG_LEVEL / ADSSH_LOG_FORMAT pair.
type LogSettings struct {
	Level slog.Level
	JSON  bool
}

// ParseLogSettings validates the two environment values. Empty means default.
func ParseLogSettings(level, format string) (LogSettings, error) {
	var s LogSettings
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "info":
		s.Level = slog.LevelInfo
	case "debug":
		s.Level = slog.LevelDebug
	case "warn", "warning":
		s.Level = slog.LevelWarn
	case "error":
		s.Level = slog.LevelError
	default:
		return s, fmt.Errorf("ADSSH_LOG_LEVEL=%q: use error, warn, info, or debug", level)
	}
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text":
	case "json":
		s.JSON = true
	default:
		return s, fmt.Errorf("ADSSH_LOG_FORMAT=%q: use text or json", format)
	}
	return s, nil
}

// NewLogger builds the process logger for w.
func NewLogger(w io.Writer, s LogSettings) *slog.Logger {
	opts := &slog.HandlerOptions{Level: s.Level}
	if s.JSON {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}
