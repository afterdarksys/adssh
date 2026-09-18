package starlarkext

// Governed filesystem READ and metadata helpers for Starlark.
//
// These extend the `fs` namespace (see fs.go) with the read side: existence and
// type tests (the shell -e/-f/-d/-x/-s equivalents), stat metadata, glob, and
// content read/checksum. Like the writers, every call is wrapped by
// GovernStarlarkValue (path "starlark.fs.*") and classified into the `fileops`
// capability group, so a capability policy gates them as one class.
//
// Threats:
//   - Content exfiltration from a restricted (menu/SSH) session. fs.read and
//     fs.checksum READ file bytes, so they refuse when the session is
//     restricted, matching the omission of sys.read_file. The metadata tests
//     (exists/is_file/is_dir/stat/glob) disclose no file content and remain
//     available; which paths they may inspect is still the Rego policy's call
//     via the govern wrapper.
//   - Unbounded reads exhausting memory. fs.read is capped at maxReadBytes and
//     refuses larger files rather than truncating silently.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.starlark.net/starlark"
)

// maxReadBytes caps a single fs.read payload. A script needing more should
// stream through a governed virtual binary instead of pulling it into memory.
const maxReadBytes = 64 << 20 // 64 MiB

// SetupFilesystemReadAPI adds the read/metadata builtins onto the existing `fs`
// dict created by SetupFilesystemAPI. It MUST be called after SetupFilesystemAPI
// so the dict exists; if it does not, it is created defensively.
func SetupFilesystemReadAPI(env starlark.StringDict, restricted bool) {
	d, ok := env["fs"].(*starlark.Dict)
	if !ok {
		d = starlark.NewDict(8)
		env["fs"] = d
	}
	_ = d.SetKey(starlark.String("exists"), starlark.NewBuiltin("exists", fsExists))
	_ = d.SetKey(starlark.String("is_file"), starlark.NewBuiltin("is_file", fsIsFile))
	_ = d.SetKey(starlark.String("is_dir"), starlark.NewBuiltin("is_dir", fsIsDir))
	_ = d.SetKey(starlark.String("stat"), starlark.NewBuiltin("stat", fsStat))
	_ = d.SetKey(starlark.String("glob"), starlark.NewBuiltin("glob", fsGlob))
	_ = d.SetKey(starlark.String("read"), makeFSRead(restricted))
	_ = d.SetKey(starlark.String("checksum"), makeFSChecksum(restricted))
}

// fs.exists(path) -> bool. False on any stat error (including permission), never
// an exception, so it reads like a shell `[ -e ]` test.
func fsExists(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	path, err := unpackPath(b, args, kwargs)
	if err != nil {
		return nil, err
	}
	_, statErr := os.Stat(path)
	return starlark.Bool(statErr == nil), nil
}

func fsIsFile(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	path, err := unpackPath(b, args, kwargs)
	if err != nil {
		return nil, err
	}
	fi, statErr := os.Stat(path)
	return starlark.Bool(statErr == nil && fi.Mode().IsRegular()), nil
}

func fsIsDir(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	path, err := unpackPath(b, args, kwargs)
	if err != nil {
		return nil, err
	}
	fi, statErr := os.Stat(path)
	return starlark.Bool(statErr == nil && fi.IsDir()), nil
}

// fs.stat(path) -> dict{size, mode, is_dir, mtime, name} or None if absent.
func fsStat(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	path, err := unpackPath(b, args, kwargs)
	if err != nil {
		return nil, err
	}
	fi, statErr := os.Stat(path)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return starlark.None, nil
		}
		return nil, fmt.Errorf("fs.stat: %v", statErr)
	}
	out := starlark.NewDict(5)
	_ = out.SetKey(starlark.String("size"), starlark.MakeInt64(fi.Size()))
	_ = out.SetKey(starlark.String("mode"), starlark.String(fmt.Sprintf("%#o", fi.Mode().Perm())))
	_ = out.SetKey(starlark.String("is_dir"), starlark.Bool(fi.IsDir()))
	_ = out.SetKey(starlark.String("mtime"), starlark.MakeInt64(fi.ModTime().Unix()))
	_ = out.SetKey(starlark.String("name"), starlark.String(fi.Name()))
	return out, nil
}

// fs.glob(pattern) -> list of matching paths (filepath.Glob semantics).
func fsGlob(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pattern string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "pattern", &pattern); err != nil {
		return nil, err
	}
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("fs.glob: %v", err)
	}
	return stringList(matches), nil
}

// makeFSRead returns fs.read(path) -> string, refused in restricted sessions and
// bounded at maxReadBytes.
func makeFSRead(restricted bool) *starlark.Builtin {
	return starlark.NewBuiltin("read", func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		path, err := unpackPath(b, args, kwargs)
		if err != nil {
			return nil, err
		}
		if restricted {
			return nil, fmt.Errorf("fs.read: refused in restricted session")
		}
		data, rerr := readCapped(path)
		if rerr != nil {
			return nil, fmt.Errorf("fs.read: %v", rerr)
		}
		return starlark.String(string(data)), nil
	})
}

// makeFSChecksum returns fs.checksum(path) -> hex sha256, refused in restricted
// sessions and bounded at maxReadBytes.
func makeFSChecksum(restricted bool) *starlark.Builtin {
	return starlark.NewBuiltin("checksum", func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		path, err := unpackPath(b, args, kwargs)
		if err != nil {
			return nil, err
		}
		if restricted {
			return nil, fmt.Errorf("fs.checksum: refused in restricted session")
		}
		data, rerr := readCapped(path)
		if rerr != nil {
			return nil, fmt.Errorf("fs.checksum: %v", rerr)
		}
		sum := sha256.Sum256(data)
		return starlark.String(hex.EncodeToString(sum[:])), nil
	})
}

// readCapped reads at most maxReadBytes and errors (rather than truncating) if
// the file is larger, so a script never silently operates on a partial file.
func readCapped(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("path is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Read one extra byte to detect oversize without loading the whole file.
	data, err := io.ReadAll(io.LimitReader(f, maxReadBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxReadBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxReadBytes)
	}
	return data, nil
}

func unpackPath(b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (string, error) {
	var path string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &path); err != nil {
		return "", err
	}
	if path == "" {
		return "", fmt.Errorf("fs.%s: path is required", b.Name())
	}
	return path, nil
}
