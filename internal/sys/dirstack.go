package sys

import (
	"sync"
)

// DirStackState is a mutex-protected directory stack used by the REPL.
// Index 0 is the bottom; last element is the current/top directory.
type DirStackState struct {
	mu     sync.Mutex
	stack  []string
	oldpwd string
}

var globalDirStack = &DirStackState{}

// DirStack returns the process-wide directory stack singleton.
func DirStack() *DirStackState { return globalDirStack }

// Init sets the initial directory (call once from main or REPL Start).
func (d *DirStackState) Init(cwd string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stack = []string{cwd}
}

// Push records oldpwd = current top, then pushes dir onto the stack.
// Does NOT call os.Chdir.
func (d *DirStackState) Push(dir string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.stack) > 0 {
		d.oldpwd = d.stack[len(d.stack)-1]
	}
	d.stack = append(d.stack, dir)
}

// Pop removes and returns the top entry.
// Returns "" if the stack has ≤ 1 entry (never pop the initial dir).
func (d *DirStackState) Pop() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.stack) <= 1 {
		return ""
	}
	top := d.stack[len(d.stack)-1]
	d.stack = d.stack[:len(d.stack)-1]
	return top
}

// OldPwd returns the previous directory (for cd -).
func (d *DirStackState) OldPwd() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.oldpwd
}

// SetOldPwd records the previous directory.
func (d *DirStackState) SetOldPwd(dir string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.oldpwd = dir
}

// Dirs returns a snapshot of the stack, top first (reversed).
func (d *DirStackState) Dirs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := len(d.stack)
	out := make([]string, n)
	for i, v := range d.stack {
		out[n-1-i] = v
	}
	return out
}
