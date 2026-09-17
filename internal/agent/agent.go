// Package agent implements the adssh instrumentation agent: a small, hardened
// HTTP listener that lets the AfterDark control-plane API ask a running adssh to
// execute NAMED, pre-approved, read-only instrumentation tasks — and nothing
// else. Every request flows through adssh's existing policy + audit chokepoint
// (security.EvaluatePolicy, security.LogCommand, the HMAC hash-chain ledger)
// exactly as a human command would.
//
// This is deliberately NOT a general remote-exec / C2 endpoint. The network can
// name only a task; the virtual binary and its arguments are read from a local,
// operator-controlled allowlist file and are never taken from the request body.
//
// Threats:
//
//	Defends against:
//	  - Unauthenticated task execution. Every task-bearing endpoint requires a
//	    bearer token in the Authorization header, compared in constant time
//	    (crypto/subtle over SHA-256 digests, so timing is length-independent). A
//	    missing/empty configured token makes the agent REFUSE TO START (fail
//	    closed); a missing or wrong request token is 401.
//	  - Arbitrary command / argument injection from the network. The request
//	    names only a task string. The vbin + fixed args come from the allowlist
//	    file. There is no field by which a client can supply a command or args.
//	  - Replay / resource exhaustion via oversized bodies. Request bodies are
//	    capped with http.MaxBytesReader; an over-cap body is 413 and is never
//	    buffered whole.
//	  - Task escalation beyond the allowlist. An unknown task is 404. Even an
//	    allowlisted task is still gated by the Rego policy (deny => 403) and is
//	    audited on every path (allowed, denied, unknown, error).
//	  - Token disclosure. The token is never logged and never echoed in an error
//	    body or header.
//
//	Does NOT defend / out of scope:
//	  - This is NOT a general RPC, remote shell, or C2. It cannot run arbitrary
//	    commands or arbitrary args; it runs only named allowlisted tasks that map
//	    to read-only virtual binaries chosen by the operator.
//	  - Transport confidentiality / authenticity. The agent speaks plain HTTP.
//	    Bind it to localhost (the default guidance) or place it behind a TLS /
//	    mTLS terminator; it does not terminate TLS itself.
//	  - Authorization semantics of the tasks themselves. The operator is
//	    responsible for allowlisting only genuinely read-only virtual binaries
//	    and for the Rego policy that governs the "instrument" agent kind.
package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/adssh/security"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

const (
	// maxRequestBody caps the accepted request body. Instrument requests are a
	// tiny JSON object; anything larger is refused (413) unread.
	maxRequestBody int64 = 64 << 10 // 64 KiB
	// maxOutputBytes caps captured virtual-binary output returned to the client.
	maxOutputBytes = 64 << 10 // 64 KiB
	// auditSource is the audit-log source label for every agent action.
	auditSource = "agent"
	// agentKind marks the AgentClaim so the Rego policy can single out
	// instrumentation-agent traffic.
	agentKind = "instrument"
)

// Server is the instrumentation agent HTTP handler + lifecycle.
type Server struct {
	tokenDigest [sha256.Size]byte
	agentID     string
	started     time.Time
	taskTimeout time.Duration

	// sem bounds concurrent instrument tasks so a chatty caller cannot exhaust
	// the host; a full channel yields 429 rather than piling work up.
	sem chan struct{}

	mu    sync.RWMutex
	tasks *TaskSet

	httpSrv *http.Server
}

// Version is the agent build version, surfaced by /v1/info so the control plane
// can inventory each host. Overridable at link time.
var Version = "dev"

// resolveAgentID gives each host a stable, distinct identity so the control
// plane can tell the fleet apart: ADSSH_AGENT_ID if set, else the hostname,
// else a safe fallback.
func resolveAgentID() string {
	if id := strings.TrimSpace(os.Getenv("ADSSH_AGENT_ID")); id != "" {
		return id
	}
	if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
		return h
	}
	return "adssh-instrument-agent"
}

// New constructs a Server. It FAILS CLOSED: an empty token is refused so the
// agent can never come up without authentication. A nil task set is treated as
// an empty (deny-everything) allowlist.
func New(token string, tasks *TaskSet) (*Server, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("agent: ADSSH_AGENT_TOKEN is empty; refusing to start (fail closed)")
	}
	if tasks == nil {
		tasks = &TaskSet{tasks: map[string]Task{}}
	}
	return &Server{
		tokenDigest: sha256.Sum256([]byte(token)),
		agentID:     resolveAgentID(),
		started:     time.Now(),
		taskTimeout: 30 * time.Second,
		sem:         make(chan struct{}, 4),
		tasks:       tasks,
	}, nil
}

// currentTasks returns the live allowlist.
func (s *Server) currentTasks() *TaskSet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tasks
}

// Handler builds the agent's HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/info", s.handleInfo)
	mux.HandleFunc("/v1/tasks", s.handleTasks)
	mux.HandleFunc("/v1/instrument", s.handleInstrument)
	return mux
}

// Start binds addr and serves the agent in a background goroutine, mirroring
// sys.EnableSSH: it reports bind errors synchronously and returns once the
// listener is up. Fail-closed configuration errors (empty token, malformed
// tasks file) surface here before the listener is opened.
//
// The agent speaks plain HTTP: addr SHOULD be a localhost address, or the agent
// SHOULD sit behind a TLS/mTLS terminator.
func Start(addr, token, tasksPath string) (*Server, error) {
	tasks, err := LoadTasks(tasksPath)
	if err != nil {
		return nil, err
	}
	s, err := New(token, tasks)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("agent: listen on %s: %w", addr, err)
	}
	s.httpSrv = &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if serveErr := s.httpSrv.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			log.Printf("agent: server error: %v", serveErr)
		}
	}()
	fmt.Printf("adssh instrumentation agent listening on %s\n", addr)
	return s, nil
}

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpSrv == nil {
		return nil
	}
	return s.httpSrv.Shutdown(ctx)
}

// ---- request / response shapes ----

type instrumentRequest struct {
	Task string `json:"task"`
	// DryRun defaults to true when the field is omitted (a pointer distinguishes
	// "absent" from an explicit false).
	DryRun *bool `json:"dry_run"`
}

type instrumentResponse struct {
	Task      string `json:"task"`
	OK        bool   `json:"ok"`
	Exit      int    `json:"exit"`
	Output    string `json:"output"`
	Truncated bool   `json:"truncated"`
}

type taskInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Risk        string `json:"risk"`
}

type tasksResponse struct {
	Tasks []taskInfo `json:"tasks"`
}

// ---- handlers ----

// handleHealth is unauthenticated by design; it reveals no task or config data.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleInfo reports host identity, version and liveness so the control plane
// can inventory the fleet. It requires auth (it discloses task count + version).
func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.authenticate(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agent_id":       s.agentID,
		"version":        Version,
		"uptime_seconds": int(time.Since(s.started).Seconds()),
		"tasks_loaded":   s.currentTasks().Len(),
	})
}

// handleTasks lists the allowlisted task names + descriptions. It requires auth.
func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.authenticate(w, r) {
		return
	}
	tasks := s.currentTasks()
	resp := tasksResponse{Tasks: make([]taskInfo, 0, tasks.Len())}
	for _, name := range tasks.Names() {
		t, _ := tasks.Get(name)
		resp.Tasks = append(resp.Tasks, taskInfo{Name: name, Description: t.Description, Risk: t.Risk})
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleInstrument is the core chokepoint: auth -> allowlist lookup -> policy ->
// dispatch, auditing on every path.
func (s *Server) handleInstrument(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.authenticate(w, r) {
		return
	}

	// Cap the body BEFORE reading a single byte of it.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "cannot read request body")
		return
	}

	var req instrumentRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	name := strings.TrimSpace(req.Task)
	if name == "" {
		writeError(w, http.StatusBadRequest, "task is required")
		return
	}
	dryRun := true
	if req.DryRun != nil {
		dryRun = *req.DryRun
	}

	task, ok := s.currentTasks().Get(name)
	if !ok {
		security.LogCommand(auditSource, fmt.Sprintf("instrument task=%q result=unknown-task", name))
		writeError(w, http.StatusNotFound, "unknown task")
		return
	}

	// Build the policy context with an Agent claim; the policy chokepoint is
	// authoritative. Note the command/args come from the allowlist, not the net.
	pctx := security.BuildPolicyContext(task.VBin, task.Args, "")
	pctx.Agent = &security.AgentClaim{
		ID:     s.agentID,
		Kind:   agentKind,
		Risk:   task.Risk,
		DryRun: dryRun,
	}

	allowed, reason, evalErr := security.EvaluatePolicy(pctx)
	if evalErr != nil {
		// Fail closed: a policy evaluation error denies.
		security.LogCommand(auditSource, fmt.Sprintf("instrument task=%q vbin=%q result=policy-error", name, task.VBin))
		writeError(w, http.StatusForbidden, "denied by policy")
		return
	}
	if !allowed {
		security.LogCommand(auditSource, fmt.Sprintf("instrument task=%q vbin=%q dry_run=%v result=denied reason=%q", name, task.VBin, dryRun, reason))
		writeError(w, http.StatusForbidden, denyMessage(reason))
		return
	}

	vb, ok := security.Lookup(task.VBin)
	if !ok {
		// Allowlist references a virtual binary that does not exist: refuse.
		security.LogCommand(auditSource, fmt.Sprintf("instrument task=%q vbin=%q result=unknown-vbin", name, task.VBin))
		writeError(w, http.StatusInternalServerError, "task maps to unknown virtual binary")
		return
	}

	// Bound concurrency: a full pool means the host is already busy; shed load
	// with 429 rather than piling on.
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		security.LogCommand(auditSource, fmt.Sprintf("instrument task=%q result=busy", name))
		writeError(w, http.StatusTooManyRequests, "agent busy; try again")
		return
	}

	security.LogCommand(auditSource, fmt.Sprintf("instrument task=%q vbin=%q dry_run=%v result=allowed", name, task.VBin, dryRun))

	// Per-task timeout: a hung virtual binary must not wedge a worker slot.
	ctx, cancel := context.WithTimeout(r.Context(), s.taskTimeout)
	defer cancel()

	fullArgs := append([]string{task.VBin}, task.Args...)
	output, truncated, exit, runErr := runVBinCaptured(ctx, vb, fullArgs)
	if runErr != nil {
		security.LogCommand(auditSource, fmt.Sprintf("instrument task=%q vbin=%q exit=%d result=ran-with-error", name, task.VBin, exit))
	}

	writeJSON(w, http.StatusOK, instrumentResponse{
		Task:      name,
		OK:        runErr == nil && exit == 0,
		Exit:      exit,
		Output:    output,
		Truncated: truncated,
	})
}

// authenticate enforces the bearer token in constant time. It writes a 401 and
// returns false on failure. The token is never logged or echoed.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) bool {
	const prefix = "Bearer "
	presented := ""
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, prefix) {
		presented = strings.TrimSpace(h[len(prefix):])
	}
	// SHA-256 both sides so the constant-time compare is independent of the
	// presented token's length (the classic ConstantTimeCompare length leak).
	got := sha256.Sum256([]byte(presented))
	if subtle.ConstantTimeCompare(got[:], s.tokenDigest[:]) == 1 {
		return true
	}
	writeError(w, http.StatusUnauthorized, "unauthorized")
	return false
}

// runVBinCaptured dispatches vb through the security registry and captures its
// stdout/stderr. Virtual binaries write to the interp HandlerContext's Stdout,
// so we drive dispatch through a throwaway interp.Runner whose StdIO is wired to
// a size-limited buffer — the same capture shape the security package tests use.
func runVBinCaptured(ctx context.Context, vb security.VirtualBinary, args []string) (output string, truncated bool, exit int, err error) {
	lw := &limitedWriter{limit: maxOutputBytes}
	runner, newErr := interp.New(
		interp.StdIO(nil, lw, lw),
		interp.ExecHandler(func(ctx context.Context, _ []string) error {
			return security.DispatchVBin(ctx, vb, args)
		}),
	)
	if newErr != nil {
		return "", false, 1, newErr
	}
	file, parseErr := syntax.NewParser().Parse(strings.NewReader("instrument"), "")
	if parseErr != nil {
		return "", false, 1, parseErr
	}
	runErr := runner.Run(ctx, file)
	exit = 0
	if runErr != nil {
		var status interp.ExitStatus
		if errors.As(runErr, &status) {
			exit = int(status)
		} else {
			exit = 1
		}
	}
	return lw.buf.String(), lw.truncated, exit, runErr
}

// denyMessage returns a client-safe denial string, defaulting when the policy
// gave no reason. It never contains the token.
func denyMessage(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "denied by policy"
	}
	return "denied by policy: " + reason
}

// limitedWriter is an io.Writer that stops appending after limit bytes and
// records whether it dropped any.
type limitedWriter struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	remaining := l.limit - l.buf.Len()
	if remaining <= 0 {
		l.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		l.buf.Write(p[:remaining])
		l.truncated = true
		return len(p), nil
	}
	return l.buf.Write(p)
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
