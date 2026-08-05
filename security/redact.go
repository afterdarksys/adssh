package security

import (
	"regexp"
	"strings"
)

const redactedSecret = "[REDACTED]"

var sensitiveTextPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`\b(?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b`),
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{30,}\b`),
	regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,}\b`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
}

var sensitiveAssignmentPattern = regexp.MustCompile(`(?i)\b(password|passwd|token|secret|api[_-]?key|access[_-]?key)\s*=\s*("[^"]*"|'[^']*'|[^\s]+)`)

// RedactSensitiveText removes common credential-shaped values from text before
// it is displayed or persisted to non-secret-specific logs. It is intentionally
// conservative: exact leased secrets are still redacted separately by lease.
func RedactSensitiveText(text string) string {
	if text == "" {
		return text
	}
	redacted := text
	for _, pattern := range sensitiveTextPatterns {
		redacted = pattern.ReplaceAllString(redacted, redactedSecret)
	}
	redacted = sensitiveAssignmentPattern.ReplaceAllStringFunc(redacted, redactSensitiveAssignment)
	return redacted
}

func redactSensitiveBytes(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	redacted := RedactSensitiveText(string(data))
	if redacted == string(data) {
		return data
	}
	return []byte(redacted)
}

func redactSensitiveAssignment(match string) string {
	index := strings.Index(match, "=")
	if index < 0 {
		return redactedSecret
	}
	return strings.TrimRight(match[:index], " \t") + "=" + redactedSecret
}
