package starlarkext

// Structured script logging: log.info / log.warn / log.error.
//
// Each call writes one `STARLARK_LOG level=… session=… msg=… k=v` event to
// the session engine's audit stream (LogEvent: flat log plus hash chain) and
// then echoes the same redacted line to the session's stderr. The govern
// wrapper gates every call as starlark.log.<level>, which is classified into
// the `audit` capability group. The namespace is omitted in restricted
// sessions, like the other I/O builtins.
//
// Threats:
//   - Secrets in logs. The message and every field are passed through
//     security.RedactSensitiveText before they are written or echoed, and
//     LogEvent redacts the whole line again.
//   - Log forgery. Values are Go-quoted, so a newline or `k=v` text inside a
//     message cannot start a new audit line or fake a field. Field names are
//     Starlark keyword identifiers.
//   - Audit flooding. One event is capped at maxLogEventBytes.
//   - Unaudited output. The echo happens only after the audit write
//     succeeds; an audit failure returns an error and echoes nothing.
//   - Unaudited success in an SSH login child. That process has no audit
//     sink (the listener holds it), so log.* fails closed there.
// It does not rate-limit calls; a policy can deny the audit capability.

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
)

const maxLogEventBytes = 64 << 10

// SetupLogAPI injects the `log` namespace into env. Restricted sessions get
// an empty namespace.
func SetupLogAPI(env starlark.StringDict, opts ExtensionOptions) {
	d := starlark.NewDict(3)
	if !opts.Restricted {
		for _, level := range []string{"info", "warn", "error"} {
			_ = d.SetKey(starlark.String(level), starlark.NewBuiltin(level, logBuiltin(opts, level)))
		}
	}
	env["log"] = d
}

func logBuiltin(opts ExtensionOptions, level string) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if len(args) != 1 {
			return nil, fmt.Errorf("log.%s: want exactly one positional argument (msg), got %d", level, len(args))
		}
		// An SSH login child has no audit sink; the listener holds it.
		// Writing nowhere and returning success would claim an audit
		// that did not happen.
		if security.RemoteGateProcess() {
			return nil, fmt.Errorf("log.%s: not available in an SSH session; run it in a local session", level)
		}
		msg, ok := starlark.AsString(args[0])
		if !ok {
			return nil, fmt.Errorf("log.%s: msg must be a string, got %s", level, args[0].Type())
		}
		session := sessionGateID(&security.SessionState{SessionID: opts.SessionID, Globals: opts.Env})
		line, err := formatLogEvent(level, session, msg, kwargs)
		if err != nil {
			return nil, fmt.Errorf("log.%s: %w", level, err)
		}
		engine := opts.Engine
		if engine == nil {
			engine = security.DefaultEngine()
		}
		if err := engine.LogEvent(line); err != nil {
			return nil, fmt.Errorf("log.%s: audit write failed: %w", level, err)
		}
		var stderr io.Writer = os.Stderr
		if opts.Err != nil {
			stderr = opts.Err
		}
		if _, err := fmt.Fprintln(stderr, line); err != nil {
			return nil, fmt.Errorf("log.%s: echo failed: %w", level, err)
		}
		return starlark.None, nil
	}
}

func formatLogEvent(level, session, msg string, kwargs []starlark.Tuple) (string, error) {
	fields := make([]string, 0, len(kwargs))
	for _, kv := range kwargs {
		key, ok := starlark.AsString(kv[0])
		if !ok {
			return "", fmt.Errorf("field name %s is not a string", kv[0].String())
		}
		value, ok := starlark.AsString(kv[1])
		if !ok {
			value = kv[1].String()
		}
		// A credential-named field loses its whole value; any other value
		// is scanned for credential-shaped text.
		if security.RedactSensitiveText(key+"=x") != key+"=x" {
			value = "[REDACTED]"
		} else {
			value = security.RedactSensitiveText(value)
		}
		fields = append(fields, key+"="+strconv.Quote(value))
	}
	sort.Strings(fields)
	var b strings.Builder
	b.WriteString("STARLARK_LOG level=")
	b.WriteString(level)
	if session != "" {
		b.WriteString(" session=")
		b.WriteString(strconv.Quote(session))
	}
	b.WriteString(" msg=")
	b.WriteString(strconv.Quote(security.RedactSensitiveText(msg)))
	for _, f := range fields {
		b.WriteString(" ")
		b.WriteString(f)
	}
	if b.Len() > maxLogEventBytes {
		return "", fmt.Errorf("event exceeds %d bytes", maxLogEventBytes)
	}
	// LogEvent redacts the whole line; doing it here too keeps the echo
	// identical to the audited text.
	return security.RedactSensitiveText(b.String()), nil
}
