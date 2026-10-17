package config

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLogSettings(t *testing.T) {
	for _, tc := range []struct {
		level, format string
		want          slog.Level
		json          bool
	}{
		{"", "", slog.LevelInfo, false},
		{"debug", "json", slog.LevelDebug, true},
		{"WARN", "Text", slog.LevelWarn, false},
		{" error ", "", slog.LevelError, false},
	} {
		s, err := ParseLogSettings(tc.level, tc.format)
		if err != nil || s.Level != tc.want || s.JSON != tc.json {
			t.Errorf("ParseLogSettings(%q,%q) = %+v, %v", tc.level, tc.format, s, err)
		}
	}
	for _, bad := range [][2]string{{"verbose", ""}, {"trace", ""}, {"", "xml"}, {"debug", "jsonl"}} {
		if _, err := ParseLogSettings(bad[0], bad[1]); err == nil {
			t.Errorf("ParseLogSettings(%q,%q) accepted", bad[0], bad[1])
		}
	}
}

func TestNewLoggerHonoursLevelAndFormat(t *testing.T) {
	var buf bytes.Buffer
	log := NewLogger(&buf, LogSettings{Level: slog.LevelInfo, JSON: true})
	log.Debug("hidden")
	log.Info("shown", "addr", "192.0.2.1:22")
	out := buf.String()
	if strings.Contains(out, "hidden") {
		t.Fatalf("debug line printed at info: %q", out)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rec); err != nil || rec["addr"] != "192.0.2.1:22" {
		t.Fatalf("json line %q: %v", out, err)
	}
}
