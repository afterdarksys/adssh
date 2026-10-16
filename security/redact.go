package security

import "regexp"

const redactedSecret = "[REDACTED]"

var sensitiveTextPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`\b(?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b`),
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{30,}\b`),
	regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,}\b`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
}

// sensitiveAssignmentPattern matches key=value where the key, optionally
// quoted, is a credential word on its own or as the last _/- separated part
// of a longer key (db_password, API_TOKEN, aws_secret_access_key). Group 1 is
// the character before the key, kept so the match can start mid-line; group 2
// is the key with its quotes. tokenizer, secretary and token_count do not match.
var sensitiveAssignmentPattern = regexp.MustCompile(`(?i)(^|[^A-Za-z0-9_-])(["']?(?:[A-Za-z0-9]+[_-])*(?:password|passwd|token|secret|api[_-]?key|access[_-]?key)["']?)\s*=\s*(?:"[^"]*"|'[^']*'|[^\s]+)`)

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
	redacted = sensitiveAssignmentPattern.ReplaceAllString(redacted, "${1}${2}="+redactedSecret)
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
