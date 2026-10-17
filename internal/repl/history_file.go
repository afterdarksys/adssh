package repl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// Threats: the history file holds every command the user typed. It is
// accepted only as a regular file the caller owns with one link, opened
// without following a symlink, and set to 0600, so a pre-planted file, link,
// or hard link (the old shared /tmp/.adssh_history fallback) cannot capture
// or redirect it. An unsafe path turns history off rather than failing the
// session. Not covered: the line editor later reopens the file by path, so
// someone who can write the history directory can still swap the file
// between this check and that open; the directory is created 0700.

// prepareHistoryFile makes path a private history file: it creates it 0600
// if missing, and otherwise requires a regular file, not a symlink, owned by
// this uid, and tightens it to 0600. An empty path means history is off.
func prepareHistoryFile(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW, 0600)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return fmt.Errorf("%s is a symbolic link", path)
		}
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if int(st.Uid) != os.Geteuid() {
			return fmt.Errorf("%s is owned by uid %d, not this user", path, st.Uid)
		}
		if st.Nlink != 1 {
			return fmt.Errorf("%s has %d hard links", path, st.Nlink)
		}
	}
	return f.Chmod(0600)
}
