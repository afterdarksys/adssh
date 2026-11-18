// adssh-userland runs a local, per-user u-root execution service.
package main

// Threats: root execution is refused; identity comes from the kernel peer UID.
// The daemon requires policy and audit configuration. This is not a sandbox
// against the owning user and does not provide remote or elevated execution.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"syscall"

	"github.com/afterdarksys/adssh/internal/userland"
	"github.com/afterdarksys/adssh/security"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	defaultSocket, err := userland.DefaultSocket()
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	socket := flag.String("socket", defaultSocket, "Unix socket in a private directory")
	worker := flag.String("worker", filepath.Join(filepath.Dir(executable), "adssh-userland-worker"), "absolute path to bundled u-root worker")
	policy := flag.String("policy", "", "required Rego policy path")
	audit := flag.String("audit", "", "required audit log path")
	entitlements := flag.String("entitlements", "", "optional entitlements path")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("userland: unexpected positional arguments")
	}
	if os.Getuid() != os.Geteuid() {
		return fmt.Errorf("userland: setuid execution is unsupported")
	}
	if os.Geteuid() == 0 {
		return fmt.Errorf("userland: run as an ordinary user, never root")
	}
	if *policy == "" || *audit == "" {
		return fmt.Errorf("userland: --policy and --audit are required")
	}
	identity, err := user.Current()
	if err != nil {
		return err
	}
	eng, err := security.NewEngine(security.EngineConfig{PolicyPath: *policy, RequirePolicy: true, AuditLogPath: *audit, EntitlementsPath: *entitlements})
	if err != nil {
		return err
	}
	const session = "userland-local"
	if err := eng.BindSessionIdentity(session, identity.Username, nil); err != nil {
		return err
	}
	defer eng.UnbindSessionIdentity(session)
	server, err := userland.NewServer(userland.Config{
		Worker:    *worker,
		Authorize: func(ctx context.Context, argv []string) error { return eng.AuthorizeCommandContext(ctx, argv, session) },
		Record: func(_ context.Context, argv []string, event string) error {
			return eng.LogEvent(fmt.Sprintf("USERLAND command=%q %s", argv[0], event))
		},
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*socket), 0700); err != nil {
		return err
	}
	listener, err := userland.Listen(*socket)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			server.Stop()
		case <-done:
		}
	}()
	fmt.Fprintf(os.Stderr, "adssh-userland listening on %s\n", *socket)
	err = server.Serve(listener)
	server.Stop()
	if ctx.Err() != nil {
		return nil
	}
	return errors.Join(err, listener.Close())
}
