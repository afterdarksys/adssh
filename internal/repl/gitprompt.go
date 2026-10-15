package repl

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	gitPromptTimeout = 200 * time.Millisecond
	gitPromptMaxOut  = 8 << 10
	gitPromptMaxName = 64
)

// gitPromptCache remembers one git status lookup for a single prompt draw.
// PROMPT and RPROMPT share it so both escapes do not start a second git.
type gitPromptCache struct {
	enabled bool
	cwd     string
	lookup  func(cwd string) string
	once    sync.Once
	seg     string
}

func (c *gitPromptCache) segment() string {
	if c == nil || !c.enabled {
		return ""
	}
	c.once.Do(func() {
		fn := c.lookup
		if fn == nil {
			fn = gitPromptSegment
		}
		c.seg = fn(c.cwd)
	})
	return c.seg
}

// gitPromptFromEnv reports whether ADSSH_GIT_PROMPT turns the segment on.
// Unset, empty, and any value other than 1, true, yes, or on stay off.
func gitPromptFromEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// applyGitPrompt handles `set gitprompt` and `set gitprompt on|off`.
// Any other line is left to the shell. An unknown value does not change the flag.
func applyGitPrompt(line string, on bool) (next bool, handled bool, err error) {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "set" || fields[1] != "gitprompt" {
		return on, false, nil
	}
	if len(fields) == 2 {
		return on, true, nil
	}
	if len(fields) == 3 {
		switch fields[2] {
		case "on":
			return true, true, nil
		case "off":
			return false, true, nil
		}
	}
	return on, true, errors.New("set gitprompt: usage: set gitprompt [on|off]")
}

// gitPromptSegment runs git status for cwd. A missing repository, a timeout,
// or any other error is an empty segment. The command is git itself, not a shell.
func gitPromptSegment(cwd string) string {
	if cwd == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), gitPromptTimeout)
	defer cancel()
	// --no-optional-locks is a global option. Apple Git rejects it after status.
	cmd := exec.CommandContext(ctx, "git", "--no-optional-locks", "-C", cwd, "status", "--porcelain=v1", "-b")
	cmd.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0")
	cmd.Stderr = io.Discard
	var out limitedBuffer
	out.remain = gitPromptMaxOut
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return ""
	}
	return formatGitStatus(out.buf.String(), out.truncated)
}

// formatGitStatus turns porcelain v1 -b output into "branch" or "branch*".
// A branch name is untrusted. Control bytes are dropped so the prompt cannot
// be rewritten. A truncated read is treated as dirty.
func formatGitStatus(out string, truncated bool) string {
	line, rest, _ := strings.Cut(out, "\n")
	if !strings.HasPrefix(line, "## ") {
		return ""
	}
	head := strings.TrimPrefix(line, "## ")
	branch := head
	if i := strings.Index(branch, "..."); i >= 0 {
		branch = branch[:i]
	}
	switch {
	case strings.HasPrefix(branch, "HEAD"):
		branch = "HEAD"
	case strings.HasPrefix(branch, "No commits yet on "):
		branch = strings.TrimPrefix(branch, "No commits yet on ")
		if i := strings.IndexAny(branch, " \t"); i >= 0 {
			branch = branch[:i]
		}
	default:
		if i := strings.IndexAny(branch, " \t"); i >= 0 {
			branch = branch[:i]
		}
	}
	branch = sanitizePromptToken(branch)
	if branch == "" {
		return ""
	}
	dirty := truncated
	if !dirty {
		for _, extra := range strings.Split(rest, "\n") {
			if strings.TrimSpace(extra) != "" {
				dirty = true
				break
			}
		}
	}
	if dirty {
		return branch + "*"
	}
	return branch
}

func sanitizePromptToken(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if n >= gitPromptMaxName {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// limitedBuffer keeps at most remain bytes and remembers that the rest was dropped.
type limitedBuffer struct {
	buf       bytes.Buffer
	remain    int
	truncated bool
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	if w.remain <= 0 {
		w.truncated = true
		return len(p), nil
	}
	if len(p) > w.remain {
		_, _ = w.buf.Write(p[:w.remain])
		w.remain = 0
		w.truncated = true
		return len(p), nil
	}
	_, _ = w.buf.Write(p)
	w.remain -= len(p)
	return len(p), nil
}
