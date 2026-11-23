package security

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"mvdan.cc/sh/v3/interp"
)

// Threats: hashes detect changes relative to an explicit baseline, not malicious
// changes by the OS account itself. State is isolated by engine and session and
// lives only for this process. Failed reads never replace a baseline. No
// background task, external notification, or durable integrity claim is made.
type watchRecord struct {
	Path          string     `json:"path"`
	SHA256        string     `json:"sha256"`
	CurrentSHA256 string     `json:"current_sha256,omitempty"`
	SetAt         time.Time  `json:"set_at"`
	CheckedAt     time.Time  `json:"checked_at"`
	ChangedAt     *time.Time `json:"changed_at,omitempty"`
	ModifiedAt    time.Time  `json:"modified_at"`
	Size          int64      `json:"size"`
	Match         bool       `json:"match"`
}
type watchKey struct{ session, path string }
type fileWatchState struct {
	sync.Mutex
	records map[watchKey]watchRecord
}

func (e *Engine) fileWatches() *fileWatchState {
	return e.extension("file-watches", func() any { return &fileWatchState{records: make(map[watchKey]watchRecord)} }).(*fileWatchState)
}

func investigationHash(ctx context.Context, path string) (digest string, info os.FileInfo, err error) {
	f, err := openInvestigationFile(ctx, path)
	if err != nil {
		return "", nil, err
	}
	defer func() {
		if e := f.Close(); err == nil {
			err = e
		}
	}()
	before, err := f.Stat()
	if err != nil {
		return "", nil, err
	}
	h := sha256.New()
	limited := &io.LimitedReader{R: f, N: investigationMaxFile + 1}
	buf := make([]byte, 32<<10)
	for {
		if err = ctx.Err(); err != nil {
			return "", nil, err
		}
		n, readErr := limited.Read(buf)
		if n > 0 {
			if _, err = h.Write(buf[:n]); err != nil {
				return "", nil, err
			}
		}
		if limited.N == 0 {
			return "", nil, fmt.Errorf("watch: file exceeds 64 MiB")
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", nil, readErr
		}
	}
	info, err = f.Stat()
	if err != nil {
		return "", nil, err
	}
	if before.Size() != info.Size() || !before.ModTime().Equal(info.ModTime()) {
		return "", nil, fmt.Errorf("watch: file changed during hashing")
	}
	return hex.EncodeToString(h.Sum(nil)), info, nil
}

type watchBinary struct{}

func (watchBinary) Name() string { return "watch" }
func (watchBinary) Description() string {
	return "Track file hashes and observation times within this shell session"
}
func (watchBinary) Usage() string {
	return "watch <set|get|remove> hash <file> | watch list (session-local; not Unix watch)"
}
func (watchBinary) Run(ctx context.Context, args []string) error {
	eng := engineFromContext(ctx)
	state := eng.fileWatches()
	session := SessionIDFromContext(ctx)
	if len(args) == 2 && args[1] == "list" {
		state.Lock()
		records := []watchRecord{}
		for key, record := range state.records {
			if key.session == session {
				records = append(records, record)
			}
		}
		state.Unlock()
		sort.Slice(records, func(i, j int) bool { return records[i].Path < records[j].Path })
		return json.NewEncoder(interp.HandlerCtx(ctx).Stdout).Encode(records)
	}
	if len(args) != 4 || args[2] != "hash" || (args[1] != "set" && args[1] != "get" && args[1] != "remove") {
		return fmt.Errorf("usage: %s", (watchBinary{}).Usage())
	}
	record, err := state.observe(ctx, eng, session, args[1], investigationPath(ctx, args[3]))
	if err != nil || record == nil {
		return err
	}
	if err := json.NewEncoder(interp.HandlerCtx(ctx).Stdout).Encode(record); err != nil {
		return err
	}
	if !record.Match {
		return fmt.Errorf("watch: hash differs from baseline")
	}
	return nil
}

// Release shared state before writing to a caller-controlled output stream.
func (state *fileWatchState) observe(ctx context.Context, eng *Engine, session, action, path string) (*watchRecord, error) {
	key := watchKey{session, path}
	state.Lock()
	defer state.Unlock()
	record, exists := state.records[key]
	if action != "set" && !exists {
		return nil, fmt.Errorf("watch: no baseline for %q", path)
	}
	if action == "remove" {
		if err := eng.LogEvent(fmt.Sprintf("WATCH_REMOVE: session=%q path=%q", session, path)); err != nil {
			return nil, err
		}
		delete(state.records, key)
		return nil, nil
	}
	if !exists && len(state.records) >= 1024 {
		return nil, fmt.Errorf("watch: engine limit of 1024 tracked files reached")
	}
	hash, info, err := investigationHash(ctx, path)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if action == "set" {
		record = watchRecord{Path: path, SHA256: hash, SetAt: now}
	}
	record.CurrentSHA256 = hash
	record.CheckedAt = now
	record.ModifiedAt = info.ModTime().UTC()
	record.Size = info.Size()
	record.Match = subtle.ConstantTimeCompare([]byte(record.SHA256), []byte(hash)) == 1
	if !record.Match && (record.ChangedAt == nil || subtle.ConstantTimeCompare([]byte(state.records[key].CurrentSHA256), []byte(hash)) != 1) {
		record.ChangedAt = &now
	}
	if err := eng.LogEvent(fmt.Sprintf("WATCH_%s: session=%q path=%q match=%t", action, session, path, record.Match)); err != nil {
		return nil, err
	}
	state.records[key] = record
	return &record, nil
}

func init() { Register(watchBinary{}) }
