package starlarkext

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"go.starlark.net/starlark"
)

func SetupContainersAPI(env starlark.StringDict) {
	d := starlark.NewDict(5)
	_ = d.SetKey(starlark.String("exec"), starlark.NewBuiltin("exec", containersExec))
	_ = d.SetKey(starlark.String("list"), starlark.NewBuiltin("list", containersList))
	_ = d.SetKey(starlark.String("audit"), starlark.NewBuiltin("audit", containersAudit))
	_ = d.SetKey(starlark.String("replay"), starlark.NewBuiltin("replay", containersReplay))
	_ = d.SetKey(starlark.String("clean"), starlark.NewBuiltin("clean", containersClean))
	env["containers"] = d
}

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
	_, _ = rand.Read(b)
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

func RunEphemeralContainer(ctx context.Context, sessionID, image string, cmdArgs []string, env map[string]string, replayOf string) (ContainerAuditRecord, error) {
	if sessionID == "" {
		sessionID = newSessionID()
	}
	if _, err := dockerCLI(ctx, "pull", image); err != nil {
		return ContainerAuditRecord{}, fmt.Errorf("containers.exec pull %s: %v", image, err)
	}

	args := []string{
		"run", "--rm",
		"--name", "adssh-" + sessionID,
		"--label", "adssh.session=" + sessionID,
		"--label", "adssh.managed=true",
	}
	for k, v := range env {
		args = append(args, "-e", k+"="+v)
	}
	args = append(args, image)
	args = append(args, cmdArgs...)

	start := time.Now()
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	err := cmd.Run()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	rec := ContainerAuditRecord{
		SessionID:  sessionID,
		Timestamp:  start.UTC().Format(time.RFC3339),
		Image:      image,
		Cmd:        cmdArgs,
		Env:        env,
		ExitCode:   exitCode,
		Stdout:     stdoutBuf.String(),
		Stderr:     stderrBuf.String(),
		DurationMs: time.Since(start).Milliseconds(),
		ReplayOf:   replayOf,
	}
	if err := writeAuditRecord(rec); err != nil {
		fmt.Fprintf(os.Stderr, "containers.exec: failed to write audit record: %v\n", err)
	}
	return rec, err
}

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

	var cmdArgs []string
	switch v := cmdVal.(type) {
	case starlark.String:
		cmdArgs = []string{"sh", "-c", string(v)}
	case *starlark.List:
		for i := 0; i < v.Len(); i++ {
			s, ok := v.Index(i).(starlark.String)
			if !ok {
				return nil, fmt.Errorf("containers.exec: cmd list must contain strings")
			}
			cmdArgs = append(cmdArgs, string(s))
		}
	default:
		return nil, fmt.Errorf("containers.exec: cmd must be a string or list")
	}

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

	rec, err := RunEphemeralContainer(context.Background(), newSessionID(), image, cmdArgs, env, "")
	if err != nil {
		return nil, err
	}
	return auditRecordToStarlark(rec), nil
}

func containersList(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return dockerJSONLines("ps", "-a", "--filter", "label=adssh.managed=true", "--format", "{{json .}}")
}

func containersAudit(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	last := 20
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

	rec, err := RunEphemeralContainer(context.Background(), newSessionID(), original.Image, original.Cmd, original.Env, sessionID)
	if err != nil {
		return nil, err
	}
	return auditRecordToStarlark(rec), nil
}

func containersClean(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	list, err := dockerJSONLines("ps", "-a", "--filter", "label=adssh.managed=true", "--format", "{{json .}}")
	if err != nil {
		return nil, err
	}
	values, ok := list.(*starlark.List)
	if !ok {
		return nil, fmt.Errorf("containers.clean: unexpected docker list result")
	}
	removed := starlark.NewList(nil)
	for i := 0; i < values.Len(); i++ {
		item, ok := values.Index(i).(*starlark.Dict)
		if !ok {
			continue
		}
		value, found, err := item.Get(starlark.String("ID"))
		if err != nil || !found {
			continue
		}
		id, ok := starlark.AsString(value)
		if !ok || id == "" {
			continue
		}
		if _, err := dockerCLI(context.Background(), "rm", "-f", id); err == nil {
			_ = removed.Append(starlark.String(id))
		}
	}
	return removed, nil
}
