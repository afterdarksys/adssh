package security

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"mvdan.cc/sh/v3/interp"
)

const investigationMaxFile = 64 << 20

// Threats: bounded regular-file reads reject devices, FIFOs, final symlinks,
// and oversized inputs. Parent directories remain subject to OS permissions;
// these commands do not provide a filesystem sandbox or an atomic snapshot.
func openInvestigationFile(ctx context.Context, path string) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && (!info.Mode().IsRegular() || info.Size() > investigationMaxFile) {
		err = fmt.Errorf("expected a regular file of at most %d bytes", investigationMaxFile)
	}
	if err != nil {
		if closeErr := f.Close(); closeErr != nil {
			return nil, fmt.Errorf("%w (close: %v)", err, closeErr)
		}
		return nil, err
	}
	return f, nil
}

func investigationPath(ctx context.Context, name string) string {
	if filepath.IsAbs(name) {
		return filepath.Clean(name)
	}
	return filepath.Join(interp.HandlerCtx(ctx).Dir, name)
}

type filterBinary struct{}

func (filterBinary) Name() string { return "filter" }
func (filterBinary) Description() string {
	return "Print file lines matching a regular expression or literal string"
}
func (filterBinary) Usage() string {
	return "filter <-r regex | -s string> <filename> (64 MiB file, 1 MiB line limit)"
}
func (filterBinary) Run(ctx context.Context, args []string) (err error) {
	if len(args) != 4 || (args[1] != "-r" && args[1] != "-s") {
		return fmt.Errorf("usage: %s", (filterBinary{}).Usage())
	}
	if len(args[2]) > 65536 {
		return fmt.Errorf("filter: pattern exceeds 64 KiB")
	}
	match := func(line string) bool { return strings.Contains(line, args[2]) }
	if args[1] == "-r" {
		re, e := regexp.Compile(args[2])
		if e != nil {
			return fmt.Errorf("filter: %w", e)
		}
		match = re.MatchString
	}
	f, err := openInvestigationFile(ctx, investigationPath(ctx, args[3]))
	if err != nil {
		return fmt.Errorf("filter: %w", err)
	}
	defer func() {
		if e := f.Close(); err == nil {
			err = e
		}
	}()
	limited := &io.LimitedReader{R: f, N: investigationMaxFile + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), (1<<20)+1)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if limited.N == 0 {
			return fmt.Errorf("filter: file exceeds 64 MiB")
		}
		if match(scanner.Text()) {
			if _, err := fmt.Fprintln(interp.HandlerCtx(ctx).Stdout, scanner.Text()); err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("filter: %w", err)
	}
	if limited.N == 0 {
		return fmt.Errorf("filter: file exceeds 64 MiB")
	}
	return nil
}
func init() { Register(filterBinary{}) }
