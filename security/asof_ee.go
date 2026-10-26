//go:build ee

// Threats: asof verifies every ledger line with the running HMAC and rejects
// a decoy prev_hash. The key file must be owner-only and exactly 32 bytes.
// Comparison checks length before the constant-time compare. A symlink, a
// wide mode, a short key, or an oversized line is chain rejected. The key
// copy is zeroed. An all-zero key is rejected. A sequence past the last
// verified entry is rejected. A close error after a successful read is
// rejected. asof does not authorize a command.
// Non-goals: asof does not rewrite the ledger and does not open it with
// os.Open.

package security

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/afterdarksys/adssh/internal/safefile"
)

var (
	errAsofRejected = errors.New("asof: chain rejected")
	errAsofUsage    = errors.New("asof: usage: asof --chain PATH --key PATH --seq N")
	// walkClose replaces the ledger close. Tests close the file themselves.
	walkClose func(*os.File) error
)

// AsofAt replays a ledger through seq and reports the allowlist and the
// latest host profile users and units at or before that sequence.
func AsofAt(chainPath, keyPath string, seq int64) (string, error) {
	if chainPath == "" || keyPath == "" || seq < 0 {
		return "", errAsofUsage
	}
	key, err := readOwnerOnly(keyPath, 32)
	if err != nil || len(key) != 32 || subtle.ConstantTimeCompare(key, make([]byte, 32)) == 1 {
		for i := range key {
			key[i] = 0
		}
		return "", errAsofRejected
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	entries, err := walkChain(chainPath, key)
	if err != nil || len(entries) == 0 || seq > entries[len(entries)-1].Seq {
		return "", errAsofRejected
	}
	return formatAsof(entries, seq), nil
}

func walkChain(path string, key []byte) (entries []ChainEntry, err error) {
	f, _, oerr := safefile.Open(nil, path)
	if oerr != nil {
		return nil, oerr
	}
	defer func() {
		var cerr error
		if walkClose != nil {
			cerr = walkClose(f)
		} else {
			cerr = f.Close()
		}
		if cerr != nil {
			err = cerr
			entries = nil
		}
	}()
	sc := newChainScanner(f)
	var prev string
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		var entry ChainEntry
		if err = json.Unmarshal([]byte(line), &entry); err != nil {
			entries = nil
			return nil, err
		}
		expected, herr := computeHash(key, prev, entry)
		if herr != nil || entry.PrevHash != prev || !hmacEqual(entry.Hash, expected) {
			entries = nil
			return nil, errors.New("asof: chain rejected")
		}
		entries = append(entries, entry)
		prev = entry.Hash
	}
	if err = sc.Err(); err != nil {
		entries = nil
		return nil, err
	}
	return entries, nil
}

func hmacEqual(a, b string) bool {
	ab := []byte(a)
	bb := []byte(b)
	if len(ab) != len(bb) {
		return false
	}
	return subtle.ConstantTimeCompare(ab, bb) == 1
}

func formatAsof(entries []ChainEntry, seq int64) string {
	var allow []string
	seen := map[string]struct{}{}
	var users, units string
	for _, entry := range entries {
		if entry.Seq > seq {
			continue
		}
		if entry.Type == "policy" && entry.Allowed != nil && *entry.Allowed {
			argv0 := entry.Command
			if i := strings.IndexAny(argv0, " \t"); i >= 0 {
				argv0 = argv0[:i]
			}
			if argv0 != "" {
				if _, ok := seen[argv0]; !ok {
					seen[argv0] = struct{}{}
					allow = append(allow, argv0)
				}
			}
		}
		if entry.Type != "event" {
			continue
		}
		cmd := entry.Command
		switch {
		case strings.HasPrefix(cmd, "HOST_PROFILE_NARROW "):
			users, units = profileUsersUnits(cmd)
		case strings.HasPrefix(cmd, "HOST_PROFILE "):
			users, units = profileUsersUnits(cmd)
		}
	}
	return fmt.Sprintf("allowlist=%s\nunits=%s\nusers=%s\n", strings.Join(allow, ","), units, users)
}

func profileUsersUnits(cmd string) (users, units string) {
	for _, field := range strings.Fields(cmd) {
		if v, ok := strings.CutPrefix(field, "users="); ok {
			users = v
		}
		if v, ok := strings.CutPrefix(field, "units="); ok {
			units = v
		}
	}
	return users, units
}

type asofBinary struct{}

func (asofBinary) Name() string        { return "asof" }
func (asofBinary) Description() string { return "Replay the audit chain" }
func (asofBinary) Usage() string {
	return "asof: usage: asof --chain PATH --key PATH --seq N"
}

func (a asofBinary) Run(ctx context.Context, args []string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if helpArgs(args) {
		return writeOut(ctx, a.Usage())
	}
	if len(args) == 0 {
		return errAsofUsage
	}
	chain, key, seq, err := parseAsofFlags(args[1:])
	if err != nil {
		return err
	}
	if _, _, err := requireSession(ctx, "asof"); err != nil {
		return err
	}
	text, err := AsofAt(chain, key, seq)
	if err != nil {
		return err
	}
	return writeOut(ctx, text)
}

func parseAsofFlags(args []string) (chain, key string, seq int64, err error) {
	var gotChain, gotKey, gotSeq bool
	for i := 0; i < len(args); i++ {
		flag := args[i]
		if flag != "--chain" && flag != "--key" && flag != "--seq" {
			return "", "", 0, errAsofUsage
		}
		if i+1 >= len(args) {
			return "", "", 0, errAsofUsage
		}
		val := args[i+1]
		i++
		switch flag {
		case "--chain":
			if gotChain || val == "" {
				return "", "", 0, errAsofUsage
			}
			gotChain, chain = true, val
		case "--key":
			if gotKey || val == "" {
				return "", "", 0, errAsofUsage
			}
			gotKey, key = true, val
		case "--seq":
			if gotSeq {
				return "", "", 0, errAsofUsage
			}
			n, nerr := strconv.ParseInt(val, 10, 64)
			if nerr != nil || n < 0 {
				return "", "", 0, errAsofUsage
			}
			gotSeq, seq = true, n
		}
	}
	if !gotChain || !gotKey || !gotSeq {
		return "", "", 0, errAsofUsage
	}
	return chain, key, seq, nil
}

func init() {
	Register(asofBinary{})
}
