//go:build ee

// Threats: a sah/1 frame is untrusted stdin. The disabled switch must not
// read or execute it. A lease_id does not authorize a command and does not
// mark the provision → enroll → execute handoff wired. Execute output is
// capped. Errors returned to the caller are fixed codes; raw exec errors
// are not passed through. This package does not open a socket and does not
// speak to systemapi or computeapi.
package sah

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path"
	"regexp"
	"strings"
)

const (
	Protocol    = "sah/1"
	Role        = "adssh"
	Handoff     = "not_wired"
	maxFrame    = 64 * 1024
	maxOutput   = 4096
	maxArgs     = 32
	maxArgBytes = 4096
	maxIDBytes  = 64
)

// Exec runs an already-validated command without a shell. stdout and stderr
// are capped again by this package. A returned error is published only when
// its text is a fixed code matching ^[a-z0-9_]{1,64}$.
type Exec func(command []string) (stdout, stderr string, exitCode int, err error)

type request struct {
	V       int      `json:"v"`
	ID      string   `json:"id"`
	Type    string   `json:"type"`
	Command []string `json:"command,omitempty"`
	LeaseID string   `json:"lease_id,omitempty"`
}

type response struct {
	V        int    `json:"v"`
	ID       string `json:"id"`
	Type     string `json:"type"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Role     string `json:"role"`
	Protocol string `json:"protocol"`
	Handoff  string `json:"handoff"`
	ExitCode *int   `json:"exit_code,omitempty"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
}

var (
	errTooLarge = errors.New("too_large")
	idPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	codePattern = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
)

// vbinNames are exact argv0 names of adssh virtual binaries. A path to an
// external binary with the same basename is not in this set, except adssh,
// sah, and adssh-mcp, which are rejected by basename so the frame cannot
// recurse into this process.
var vbinNames = map[string]struct{}{
	"jq": {}, "yq": {}, "http": {}, "mirror": {}, "admin": {}, "identity": {},
	"gateway": {}, "lease": {}, "elevate": {}, "??": {}, "cmdgen": {},
	"package": {}, "darkscan": {}, "grant": {}, "vbins": {}, "cm": {},
	"evidence": {}, "4eyes": {}, "why": {}, "proc": {}, "par": {}, "nav": {},
	"help": {}, "pick": {}, "audit": {}, "runbook": {}, "plugin": {}, "memforensics": {}, "guard": {},
	"from": {}, "where": {}, "select": {}, "to": {},
}

// Handle reads at most one sah/1 frame when enabled is true. When enabled is
// false it writes sah_disabled and does not read in or call exec.
func Handle(enabled bool, in io.Reader, out io.Writer, exec Exec) int {
	if out == nil {
		out = io.Discard
	}
	if !enabled {
		writeResponse(out, response{
			V: 1, Type: "error", OK: false, Error: "sah_disabled",
			Role: Role, Protocol: Protocol, Handoff: Handoff,
		})
		return 2
	}
	frame, err := readFrame(in)
	if err != nil {
		code := "bad_frame"
		if errors.Is(err, errTooLarge) {
			code = "too_large"
		}
		writeResponse(out, fail("", "error", code))
		return 2
	}
	dec := json.NewDecoder(bytes.NewReader(frame))
	dec.DisallowUnknownFields()
	var req request
	if err := dec.Decode(&req); err != nil {
		writeResponse(out, fail("", "error", "bad_frame"))
		return 2
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		writeResponse(out, fail(req.ID, "error", "bad_frame"))
		return 2
	}
	if req.V != 1 {
		writeResponse(out, fail(req.ID, "error", "version_rejected"))
		return 2
	}
	if !idPattern.MatchString(req.ID) || len(req.ID) > maxIDBytes {
		writeResponse(out, fail(req.ID, "error", "bad_id"))
		return 2
	}
	switch req.Type {
	case "hello":
		writeResponse(out, response{
			V: 1, ID: req.ID, Type: "hello", OK: true,
			Role: Role, Protocol: Protocol, Handoff: Handoff,
		})
		return 0
	case "execute":
		return handleExecute(out, req, exec)
	default:
		writeResponse(out, fail(req.ID, req.Type, "type_rejected"))
		return 2
	}
}

func handleExecute(out io.Writer, req request, exec Exec) int {
	if err := validateCommand(req.Command); err != nil {
		writeResponse(out, fail(req.ID, "execute", "command_rejected"))
		return 2
	}
	if exec == nil {
		writeResponse(out, fail(req.ID, "execute", "execute_unavailable"))
		return 2
	}
	stdout, stderr, exitCode, err := exec(req.Command)
	if err != nil {
		writeResponse(out, fail(req.ID, "execute", safeCode(err)))
		return 2
	}
	code := exitCode
	writeResponse(out, response{
		V: 1, ID: req.ID, Type: "execute", OK: true,
		Role: Role, Protocol: Protocol, Handoff: Handoff,
		ExitCode: &code,
		Stdout:   capBytes(stdout),
		Stderr:   capBytes(stderr),
	})
	return 0
}

func validateCommand(command []string) error {
	if len(command) < 1 || len(command) > maxArgs {
		return errors.New("command_rejected")
	}
	for _, arg := range command {
		if len(arg) > maxArgBytes || strings.ContainsRune(arg, 0) {
			return errors.New("command_rejected")
		}
	}
	argv0 := command[0]
	if argv0 == "" || strings.TrimSpace(argv0) == "" {
		return errors.New("command_rejected")
	}
	base := argv0
	if strings.Contains(argv0, "/") {
		base = path.Base(argv0)
	}
	switch base {
	case "adssh", "sah", "adssh-mcp":
		return errors.New("command_rejected")
	}
	if _, ok := vbinNames[argv0]; ok {
		return errors.New("command_rejected")
	}
	return nil
}

func readFrame(in io.Reader) ([]byte, error) {
	if in == nil {
		return nil, io.EOF
	}
	br := bufio.NewReader(in)
	var buf bytes.Buffer
	for {
		b, err := br.ReadByte()
		if err != nil {
			if err == io.EOF {
				if buf.Len() == 0 {
					return nil, io.EOF
				}
				return buf.Bytes(), nil
			}
			return nil, err
		}
		if b == '\n' {
			if buf.Len() == 0 {
				return nil, io.ErrUnexpectedEOF
			}
			return buf.Bytes(), nil
		}
		if buf.Len() >= maxFrame {
			return nil, errTooLarge
		}
		buf.WriteByte(b)
	}
}

func fail(id, typ, code string) response {
	if typ == "" {
		typ = "error"
	}
	return response{
		V: 1, ID: id, Type: typ, OK: false, Error: code,
		Role: Role, Protocol: Protocol, Handoff: Handoff,
	}
}

func writeResponse(out io.Writer, resp response) {
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(resp)
}

func capBytes(s string) string {
	if len(s) <= maxOutput {
		return s
	}
	return s[:maxOutput]
}

func safeCode(err error) string {
	if err == nil {
		return "execute_failed"
	}
	msg := err.Error()
	if codePattern.MatchString(msg) {
		return msg
	}
	return "execute_failed"
}
