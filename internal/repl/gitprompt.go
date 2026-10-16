package repl

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/afterdarksys/adssh/security"
)

// Threats: \g shows the branch of the repository the operator has cd'd into,
// and that repository may be hostile. The segment never runs git or any other
// program, so core.fsmonitor, filter drivers, and hooks in the repo's config
// cannot execute. It reads .git/HEAD, or follows one `gitdir:` file once. A
// relative gitdir may climb at most one directory, an absolute one must sit
// under $HOME or the session cwd, and a second gitdir file is not followed.
// Files are opened without following symlinks and without blocking, and must
// be small regular files, so a FIFO or a device cannot hang the prompt. The
// branch name is untrusted: C0, C1, DEL, and Unicode format characters
// (bidi overrides, zero-width) are dropped and it is capped at 64 runes. The
// work-tree dirty marker is gone: it needed git status, which runs repo
// config. The toggle is refused in restricted mode and in an SSH session.
// This does not stop a branch name that is merely misleading text.

const (
	gitPromptMaxName  = 64
	gitPromptMaxFile  = 4096
	gitPromptMaxDepth = 128
)

// gitPromptCache remembers one HEAD lookup for a single prompt draw.
// PROMPT and RPROMPT share it so both escapes do one lookup.
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

// gitPromptPermitted reports whether this session may show the segment.
// Restricted mode and an SSH session child never do.
func gitPromptPermitted(restricted, sshChild bool) bool {
	return !restricted && !sshChild
}

// gitPromptInitial is the starting state: ADSSH_GIT_PROMPT, when permitted.
func gitPromptInitial(env string, allowed bool) bool {
	return allowed && gitPromptFromEnv(env)
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

// handleGitPromptLine applies a `set gitprompt` line and audits a change or a
// refusal. Turning it on is refused when the session is not permitted.
func handleGitPromptLine(line string, cur, allowed bool, out, errOut io.Writer) (next bool, handled bool) {
	next, handled, err := applyGitPrompt(line, cur)
	if !handled {
		return cur, false
	}
	if err != nil {
		fmt.Fprintf(errOut, "%v\n", err)
		return cur, true
	}
	if next && !allowed {
		logGitPrompt("refused", errOut)
		fmt.Fprintln(errOut, "set gitprompt: not available in restricted mode or an SSH session")
		return false, true
	}
	state := "off"
	if next {
		state = "on"
	}
	if next != cur {
		logGitPrompt(state, errOut)
	}
	fmt.Fprintf(out, "gitprompt %s\n", state)
	return next, true
}

func logGitPrompt(action string, errOut io.Writer) {
	if err := security.DefaultEngine().LogEvent("GITPROMPT action=" + action); err != nil {
		fmt.Fprintf(errOut, "adssh: warning: audit gitprompt: %v\n", err)
	}
}

// gitPromptSegment returns the branch or short detached hash for cwd. A
// missing repository or any read error is an empty segment.
func gitPromptSegment(cwd string) string {
	if cwd == "" {
		return ""
	}
	gitDir := findGitDir(filepath.Clean(cwd))
	if gitDir == "" {
		return ""
	}
	head, ok := readSmallFile(filepath.Join(gitDir, "HEAD"))
	if !ok {
		return ""
	}
	return sanitizePromptToken(parseGitHead(head))
}

// findGitDir walks up from cwd to the first .git entry and returns the
// directory that holds HEAD, or "".
func findGitDir(cwd string) string {
	dir := cwd
	for i := 0; i < gitPromptMaxDepth; i++ {
		dotGit := filepath.Join(dir, ".git")
		if info, err := os.Stat(dotGit); err == nil {
			if info.IsDir() {
				return dotGit
			}
			if info.Mode().IsRegular() {
				return followGitdirFile(dir, dotGit, cwd)
			}
			return ""
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
	return ""
}

// followGitdirFile resolves a `gitdir: <path>` file once.
func followGitdirFile(dir, dotGit, cwd string) string {
	data, ok := readSmallFile(dotGit)
	if !ok {
		return ""
	}
	line, _, _ := strings.Cut(data, "\n")
	target, found := strings.CutPrefix(strings.TrimSpace(line), "gitdir:")
	target = strings.TrimSpace(target)
	if !found || target == "" {
		return ""
	}
	var resolved string
	if filepath.IsAbs(target) {
		resolved = filepath.Clean(target)
		home, _ := os.UserHomeDir()
		if !pathWithin(resolved, home) && !pathWithin(resolved, cwd) {
			return ""
		}
	} else {
		rel := filepath.Clean(target)
		ups := 0
		for _, part := range strings.Split(rel, string(filepath.Separator)) {
			if part != ".." {
				break
			}
			ups++
		}
		if ups > 1 {
			return ""
		}
		resolved = filepath.Join(dir, rel)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return ""
	}
	return resolved
}

func pathWithin(path, root string) bool {
	if root == "" {
		return false
	}
	root = filepath.Clean(root)
	if root == string(filepath.Separator) {
		return false
	}
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

// readSmallFile reads a regular file of at most gitPromptMaxFile bytes. It
// does not follow a symlink and does not block on a FIFO or a device.
func readSmallFile(path string) (string, bool) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > gitPromptMaxFile {
		return "", false
	}
	data, err := io.ReadAll(io.LimitReader(f, gitPromptMaxFile))
	if err != nil {
		return "", false
	}
	return string(data), true
}

// parseGitHead turns HEAD into a branch name or a 7-character short hash.
func parseGitHead(head string) string {
	line, _, _ := strings.Cut(head, "\n")
	line = strings.TrimSpace(line)
	if ref, ok := strings.CutPrefix(line, "ref:"); ok {
		branch, ok := strings.CutPrefix(strings.TrimSpace(ref), "refs/heads/")
		if !ok {
			return ""
		}
		return branch
	}
	if (len(line) == 40 || len(line) == 64) && isLowerHex(line) {
		return line[:7]
	}
	return ""
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// sanitizePromptToken drops control and format characters and caps the rune count.
func sanitizePromptToken(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r == utf8.RuneError || r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) ||
			unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
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
