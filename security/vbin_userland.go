package security

// Threats: authorization is applied to the actual child argv, not just the
// wrapper. The daemon authenticates independently. No local-exec fallback and
// no client identity claims cross the socket.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"syscall"
	"time"

	"github.com/afterdarksys/adssh/internal/userland"
	"github.com/afterdarksys/adssh/internal/userland/pb"
	"mvdan.cc/sh/v3/interp"
)

type userlandBinary struct{}

func init() {
	Register(userlandBinary{})
	RegisterHelp(HelpEntry{Name: "userland", Category: "vbin", Summary: userlandBinary{}.Description(), Usage: userlandBinary{}.Usage(),
		Description: "Execute bundled u-root tools using a local per-user gRPC daemon. Both wrapper and child command are governed. No host fallback. See docs/userland.md for setup and compatibility.",
		Examples:    []HelpExample{{Command: "userland list", Description: "Discover the daemon command catalog"}, {Command: "userland exec ls -l", Description: "List the current directory using the bundled worker"}},
		Tags:        []string{"grpc", "u-root", "daemon"},
	})
}
func (userlandBinary) Name() string { return "userland" }
func (userlandBinary) Description() string {
	return "Run bundled u-root commands through a local per-user daemon"
}
func (userlandBinary) Usage() string {
	return "userland [--socket /absolute/path] list | exec <cat|find|grep|head|ls> [args...]"
}
func (userlandBinary) Run(ctx context.Context, args []string) (err error) {
	hc := interp.HandlerCtx(ctx)
	socket, err := userland.DefaultSocket()
	if err != nil {
		return err
	}
	args = args[1:]
	if len(args) >= 2 && args[0] == "--socket" {
		socket = args[1]
		args = args[2:]
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: %s", userlandBinary{}.Usage())
	}
	var start *pb.Start
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("userland list: unexpected arguments")
		}
	case "exec":
		start = &pb.Start{Argv: args[1:], Directory: hc.Dir}
		if err := userland.ValidateStart(start); err != nil {
			return err
		}
		eng := engineFromContext(ctx)
		if err := eng.AuthorizeCommandContext(ctx, start.Argv, SessionIDFromContext(ctx)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("usage: %s", userlandBinary{}.Usage())
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := userland.Dial(ctx, socket)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, conn.Close()) }()
	if start == nil {
		response, err := pb.NewUserlandClient(conn).Describe(ctx, &pb.DescribeRequest{})
		if err != nil {
			return err
		}
		return json.NewEncoder(hc.Stdout).Encode(response)
	}
	code, err := userland.Execute(ctx, conn, start, hc.Stdin, hc.Stdout, hc.Stderr)
	if err != nil {
		// An early pipeline consumer is normal shell behavior. Return a process
		// status so mvdan can apply last-command/pipefail semantics, rather than
		// treating the writer's EPIPE as a fatal interpreter error.
		if errors.Is(err, syscall.EPIPE) {
			return interp.NewExitStatus(uint8(128 + syscall.SIGPIPE))
		}
		return err
	}
	if code != 0 {
		return interp.NewExitStatus(uint8(code))
	}
	return nil
}
