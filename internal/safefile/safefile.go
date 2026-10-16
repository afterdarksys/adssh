// Package safefile opens and reads small local files that adssh trusts, such
// as plugin sources and the guard config, without following a symlink.
//
// Threats:
//   - A symlink swapped in for the file. The final component is opened with
//     O_NOFOLLOW; a symlink fails with ErrSymlink.
//   - A check-then-open race. Every check runs on the opened descriptor
//     (fstat), not on the path.
//   - A FIFO or device that blocks or never ends. O_NONBLOCK keeps open from
//     waiting, and anything that is not a regular file fails with
//     ErrNotRegular before a read.
//   - An oversized file, or one that grows while it is read. ReadAll refuses
//     a size over max and reads at most max+1 bytes.
//
// It does not check ownership or permission bits. Callers do that on the
// returned FileInfo, because each caller words and scopes the rule.
package safefile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	// ErrSymlink is returned when the named file is a symlink.
	ErrSymlink = errors.New("is a symlink")
	// ErrNotRegular is returned when the named file is not a regular file.
	ErrNotRegular = errors.New("is not a regular file")
	// ErrTooLarge is returned when the file is larger than the caller's max.
	ErrTooLarge = errors.New("is too large")
)

// Open opens name read-only without following a final symlink. With a
// non-nil dir, name is resolved relative to that directory descriptor. The
// returned FileInfo comes from fstat on the opened descriptor. A missing file
// returns an error that satisfies os.IsNotExist. The caller closes the file.
func Open(dir *os.File, name string) (*os.File, os.FileInfo, error) {
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	var fd int
	var err error
	if dir != nil {
		fd, err = unix.Openat(int(dir.Fd()), name, flags, 0)
		runtime.KeepAlive(dir)
	} else {
		fd, err = unix.Open(name, flags, 0)
	}
	if err != nil {
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK) {
			return nil, nil, fmt.Errorf("%s %w", name, ErrSymlink)
		}
		return nil, nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		if cerr := unix.Close(fd); cerr != nil {
			return nil, nil, fmt.Errorf("open %s: %w", name, cerr)
		}
		return nil, nil, fmt.Errorf("open %s: invalid descriptor", name)
	}
	info, err := f.Stat()
	if err != nil {
		return nil, nil, closeWith(f, err)
	}
	if !info.Mode().IsRegular() {
		return nil, nil, closeWith(f, fmt.Errorf("%s %w", name, ErrNotRegular))
	}
	return f, info, nil
}

// ReadAll reads f, which Open returned with info, and fails with
// ErrTooLarge when it holds more than max bytes. It does not close f.
func ReadAll(f *os.File, info os.FileInfo, max int64) ([]byte, error) {
	if info.Size() > max {
		return nil, fmt.Errorf("%s %w", info.Name(), ErrTooLarge)
	}
	body, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("%s %w", info.Name(), ErrTooLarge)
	}
	return body, nil
}

func closeWith(f *os.File, err error) error {
	if cerr := f.Close(); cerr != nil {
		return fmt.Errorf("%w (close: %v)", err, cerr)
	}
	return err
}
