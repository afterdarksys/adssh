package starlarkext

// Governed filesystem writes for Starlark.
//
// Starlark is hermetic by design: it cannot touch the filesystem on its own.
// That sandbox is a feature — the ONLY way a script reaches the outside world is
// through a builtin adssh chooses to expose, and every such builtin is wrapped
// by GovernStarlarkValue (govern.go), so a call to fs.write is independently
// authorized by the security engine (path "starlark.fs.write") before it runs.
// These builtins add the write capability WITHOUT giving up that property: they
// are policy-gated by the wrapper, refused outright in restricted sessions,
// size-bounded, and audited on every call. A raw io.write in an embedded Lua or
// JS runtime would skip all of that; this does not.
//
// Threats:
//   - Ungoverned writes. Every call is authorized by the govern wrapper and
//     LogEvent-audited into the hash-chain ledger here.
//   - Sandbox escape from restricted (menu/SSH) sessions. All writers refuse
//     when the session is restricted.
//   - Unbounded writes filling a disk. Content is capped at maxWriteBytes.
// It does NOT sanitize paths — which paths are writable is the Rego policy's
// job (enforced by the govern wrapper), not this layer's.

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
)

// maxWriteBytes caps a single fs.write/fs.append payload. A script that needs to
// move more than this should stage a file and use a governed virtual binary.
const maxWriteBytes = 64 << 20 // 64 MiB

// SetupFilesystemAPI injects the governed `fs` namespace into env. The restricted
// flag is captured per session (like sec.is_restricted) so a restricted and an
// unrestricted session can coexist in one process without clobbering each other.
func SetupFilesystemAPI(env starlark.StringDict, restricted bool) {
	fsDict := starlark.NewDict(3)
	_ = fsDict.SetKey(starlark.String("write"), makeFSWrite(restricted, false))
	_ = fsDict.SetKey(starlark.String("append"), makeFSWrite(restricted, true))
	_ = fsDict.SetKey(starlark.String("mkdir"), makeFSMkdir(restricted))
	env["fs"] = fsDict
}

// makeFSWrite returns fs.write (truncating) or fs.append, bound to this session's
// restricted flag. Signature: fs.write(path, content, mode=0o644).
func makeFSWrite(restricted, appendMode bool) *starlark.Builtin {
	name := "write"
	if appendMode {
		name = "append"
	}
	return starlark.NewBuiltin(name, func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var path, content string
		mode := 0o644
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &path, "content", &content, "mode?", &mode); err != nil {
			return nil, err
		}
		if restricted {
			return nil, fmt.Errorf("fs.%s: refused in restricted session", name)
		}
		if path == "" {
			return nil, fmt.Errorf("fs.%s: path is required", name)
		}
		if len(content) > maxWriteBytes {
			return nil, fmt.Errorf("fs.%s: content exceeds %d bytes", name, maxWriteBytes)
		}
		flags := os.O_CREATE | os.O_WRONLY
		if appendMode {
			flags |= os.O_APPEND
		} else {
			flags |= os.O_TRUNC
		}
		f, err := os.OpenFile(path, flags, os.FileMode(mode))
		if err != nil {
			return nil, fmt.Errorf("fs.%s: %v", name, err)
		}
		n, werr := f.WriteString(content)
		cerr := f.Close()
		if werr != nil {
			return nil, fmt.Errorf("fs.%s: %v", name, werr)
		}
		if cerr != nil {
			return nil, fmt.Errorf("fs.%s: %v", name, cerr)
		}
		security.LogEvent(fmt.Sprintf("STARLARK_FS: %s path=%q bytes=%d mode=%#o", name, path, n, mode))
		return starlark.MakeInt(n), nil
	})
}

// makeFSMkdir returns fs.mkdir(path, mode=0o755), creating parents (MkdirAll).
func makeFSMkdir(restricted bool) *starlark.Builtin {
	return starlark.NewBuiltin("mkdir", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var path string
		mode := 0o755
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &path, "mode?", &mode); err != nil {
			return nil, err
		}
		if restricted {
			return nil, fmt.Errorf("fs.mkdir: refused in restricted session")
		}
		if path == "" {
			return nil, fmt.Errorf("fs.mkdir: path is required")
		}
		if err := os.MkdirAll(filepath.Clean(path), os.FileMode(mode)); err != nil {
			return nil, fmt.Errorf("fs.mkdir: %v", err)
		}
		security.LogEvent(fmt.Sprintf("STARLARK_FS: mkdir path=%q mode=%#o", path, mode))
		return starlark.None, nil
	})
}
