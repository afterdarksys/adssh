package starlarkext

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/docker/docker/api/types/container"
	dockerimage "github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"go.starlark.net/starlark"
)

// SetupContainersAPI registers the containers.* namespace into the Starlark environment.
//
// Every execution is:
//   - Fully ephemeral (container removed after exit)
//   - Audit-logged to ~/.adssh/container_audit.jsonl (append-only JSONL)
//   - Replayable by session_id
//
// Starlark API:
//
//	result = containers.exec(image="ubuntu:22.04", cmd=["ls","-la"], env={"FOO":"bar"})
//	containers.list()           # active ephemeral containers
//	containers.audit(last=20)   # recent audit entries
//	containers.replay("abc123") # re-run exact session
//	containers.clean()          # remove any dangling ephemeral containers
func SetupContainersAPI(env starlark.StringDict) {
	d := starlark.NewDict(5)
	d.SetKey(starlark.String("exec"), starlark.NewBuiltin("exec", containersExec))
	d.SetKey(starlark.String("list"), starlark.NewBuiltin("list", containersList))
	d.SetKey(starlark.String("audit"), starlark.NewBuiltin("audit", containersAudit))
	d.SetKey(starlark.String("replay"), starlark.NewBuiltin("replay", containersReplay))
	d.SetKey(starlark.String("clean"), starlark.NewBuiltin("clean", containersClean))
	env["containers"] = d
}

// ContainerAuditRecord is persisted as one JSON line per execution.
type ContainerAuditRecord struct {
	SessionID  string            `json:"session_id"`
	Timestamp  string            `json:"timestamp"`
	Image      string            `json:"image"`
	Cmd        []string          `json:"cmd"`
	Env        map[string]string `json:"env,omitempty"`
	ExitCode   int               `json:"exit_code"`
	Stdout     string            `json:"stdout"`
	Stderr     string            `json:"stderr"`
	DurationMs int64             `json:"duration_ms"`
	ReplayOf   string            `json:"replay_of,omitempty"`
}

func containerAuditPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".adssh", "container_audit.jsonl")
}

func writeAuditRecord(rec ContainerAuditRecord) error {
	path := containerAuditPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(rec)
}

func readAuditRecords() ([]ContainerAuditRecord, error) {
	path := containerAuditPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var records []ContainerAuditRecord
	dec := json.NewDecoder(bytes.NewReader(data))
	for dec.More() {
		var rec ContainerAuditRecord
		if err := dec.Decode(&rec); err != nil {
			continue
		}
		records = append(records, rec)
	}
	return records, nil
}

func newSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func auditRecordToStarlark(rec ContainerAuditRecord) *starlark.Dict {
	env := make(map[string]string)
	for k, v := range rec.Env {
		env[k] = v
	}
	return makeDict(
		"session_id", rec.SessionID,
		"timestamp", rec.Timestamp,
		"image", rec.Image,
		"cmd", rec.Cmd,
		"env", env,
		"exit_code", int64(rec.ExitCode),
		"stdout", rec.Stdout,
		"stderr", rec.Stderr,
		"duration_ms", rec.DurationMs,
		"replay_of", rec.ReplayOf,
	)
}

// runContainer is the core execution engine used by both exec and replay.
func runContainer(ctx context.Context, sessionID, image string, cmd []string, env map[string]string, replayOf string) (ContainerAuditRecord, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return ContainerAuditRecord{}, fmt.Errorf("docker client: %v", err)
	}
	defer cli.Close()

	// Pull image if not present
	rc, err := cli.ImagePull(ctx, image, dockerimage.PullOptions{})
	if err != nil {
		return ContainerAuditRecord{}, fmt.Errorf("containers.exec pull %s: %v", image, err)
	}
	io.Copy(io.Discard, rc)
	rc.Close()

	// Build env slice
	var envSlice []string
	for k, v := range env {
		envSlice = append(envSlice, k+"="+v)
	}

	start := time.Now()
	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: image,
		Cmd:   cmd,
		Env:   envSlice,
		Labels: map[string]string{
			"adssh.session": sessionID,
			"adssh.managed": "true",
		},
	}, &container.HostConfig{
		AutoRemove: false, // we remove manually after capturing logs
	}, nil, nil, "adssh-"+sessionID)
	if err != nil {
		return ContainerAuditRecord{}, fmt.Errorf("containers.exec create: %v", err)
	}
	containerID := resp.ID

	defer cli.ContainerRemove(context.Background(), containerID, container.RemoveOptions{Force: true})

	if err := cli.ContainerStart(ctx, containerID, container.StartOptions{}); err != nil {
		return ContainerAuditRecord{}, fmt.Errorf("containers.exec start: %v", err)
	}

	// Capture logs
	logOpts := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
	}
	logRC, err := cli.ContainerLogs(ctx, containerID, logOpts)
	if err != nil {
		return ContainerAuditRecord{}, fmt.Errorf("containers.exec logs: %v", err)
	}
	defer logRC.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	stdcopy.StdCopy(&stdoutBuf, &stderrBuf, logRC)

	// Wait for exit
	statusCh, errCh := cli.ContainerWait(ctx, containerID, container.WaitConditionNotRunning)
	var exitCode int
	select {
	case status := <-statusCh:
		exitCode = int(status.StatusCode)
	case err := <-errCh:
		if err != nil {
			exitCode = -1
		}
	}

	rec := ContainerAuditRecord{
		SessionID:  sessionID,
		Timestamp:  start.UTC().Format(time.RFC3339),
		Image:      image,
		Cmd:        cmd,
		Env:        env,
		ExitCode:   exitCode,
		Stdout:     stdoutBuf.String(),
		Stderr:     stderrBuf.String(),
		DurationMs: time.Since(start).Milliseconds(),
		ReplayOf:   replayOf,
	}
	writeAuditRecord(rec)
	return rec, nil
}

// ── Starlark builtins ─────────────────────────────────────────────────────────

func containersExec(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var image string
	var cmdVal starlark.Value
	var envVal *starlark.Dict
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"image", &image,
		"cmd", &cmdVal,
		"env?", &envVal,
	); err != nil {
		return nil, err
	}

	// Parse cmd: accept string or list
	var cmd []string
	switch v := cmdVal.(type) {
	case starlark.String:
		cmd = []string{"sh", "-c", string(v)}
	case *starlark.List:
		for i := 0; i < v.Len(); i++ {
			s, ok := v.Index(i).(starlark.String)
			if !ok {
				return nil, fmt.Errorf("containers.exec: cmd list must contain strings")
			}
			cmd = append(cmd, string(s))
		}
	default:
		return nil, fmt.Errorf("containers.exec: cmd must be a string or list")
	}

	// Parse env dict
	env := make(map[string]string)
	if envVal != nil {
		for _, kv := range envVal.Items() {
			k, ok1 := kv[0].(starlark.String)
			v, ok2 := kv[1].(starlark.String)
			if ok1 && ok2 {
				env[string(k)] = string(v)
			}
		}
	}

	sessionID := newSessionID()
	rec, err := runContainer(context.Background(), sessionID, image, cmd, env, "")
	if err != nil {
		return nil, err
	}
	return auditRecordToStarlark(rec), nil
}

func containersList(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("docker client: %v", err)
	}
	defer cli.Close()

	containers, err := cli.ContainerList(context.Background(), container.ListOptions{All: false})
	if err != nil {
		return nil, fmt.Errorf("containers.list: %v", err)
	}

	var results []starlark.Value
	for _, c := range containers {
		if c.Labels["adssh.managed"] != "true" {
			continue
		}
		results = append(results, makeDict(
			"id", c.ID[:12],
			"image", c.Image,
			"status", c.Status,
			"session", c.Labels["adssh.session"],
		))
	}
	return starlark.NewList(results), nil
}

func containersAudit(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var last int
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "last?", &last); err != nil {
		return nil, err
	}
	if last <= 0 {
		last = 20
	}
	records, err := readAuditRecords()
	if err != nil {
		return nil, fmt.Errorf("containers.audit: %v", err)
	}
	// Return last N
	if len(records) > last {
		records = records[len(records)-last:]
	}
	var results []starlark.Value
	for _, rec := range records {
		results = append(results, auditRecordToStarlark(rec))
	}
	return starlark.NewList(results), nil
}

func containersReplay(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var sessionID string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "session_id", &sessionID); err != nil {
		return nil, err
	}
	records, err := readAuditRecords()
	if err != nil {
		return nil, fmt.Errorf("containers.replay: %v", err)
	}
	var original *ContainerAuditRecord
	for i := range records {
		if records[i].SessionID == sessionID {
			original = &records[i]
			break
		}
	}
	if original == nil {
		return nil, fmt.Errorf("containers.replay: session %s not found in audit log", sessionID)
	}

	newID := newSessionID()
	rec, err := runContainer(context.Background(), newID, original.Image, original.Cmd, original.Env, sessionID)
	if err != nil {
		return nil, err
	}
	return auditRecordToStarlark(rec), nil
}

func containersClean(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("docker client: %v", err)
	}
	defer cli.Close()

	containers, err := cli.ContainerList(context.Background(), container.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("containers.clean: %v", err)
	}

	var removed []starlark.Value
	for _, c := range containers {
		if c.Labels["adssh.managed"] != "true" {
			continue
		}
		cli.ContainerRemove(context.Background(), c.ID, container.RemoveOptions{Force: true})
		removed = append(removed, starlark.String(c.ID[:12]))
	}
	return starlark.NewList(removed), nil
}
