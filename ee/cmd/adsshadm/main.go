//go:build ee

// Command adsshadm administers a running adssh through its local admin API.
//
// With no command it opens an adsshadm> prompt with completion; with a
// command it runs that one command and exits. It talks only to the admin API
// started by `adssh admin serve` (loopback or a Unix socket).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"
)

var version = "dev"

const usageText = `usage: adsshadm [--url URL] [--key-file PATH] [--json] [--yes] [command [args...]]

With no command, adsshadm opens an interactive adsshadm> prompt.

  --url URL        admin API: unix:/path (preferred) or http://127.0.0.1:port
                   (default $ADSSH_ADMIN_URL, else http://127.0.0.1:8787)
  --key-file PATH  0600 file holding one admin key (default $ADSSH_ADMIN_KEY_FILE)
  --json           print raw JSON instead of tables
  --yes            do not ask before approve, deny, unban, or snoop

Commands:
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(argv []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("adsshadm", flag.ContinueOnError)
	fs.SetOutput(stderr)
	urlFlag := fs.String("url", os.Getenv("ADSSH_ADMIN_URL"), "")
	keyFile := fs.String("key-file", os.Getenv("ADSSH_ADMIN_KEY_FILE"), "")
	jsonOut := fs.Bool("json", false, "")
	yes := fs.Bool("yes", false, "")
	showVersion := fs.Bool("version", false, "")
	fs.Usage = func() {
		fmt.Fprint(stderr, usageText)
		(&app{out: stderr}).printHelp()
	}
	if err := fs.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "adsshadm", version)
		return 0
	}
	ep, err := parseEndpoint(*urlFlag)
	if err != nil {
		fmt.Fprintln(stderr, "adsshadm:", err)
		return 2
	}
	if err := checkSocket(ep); err != nil {
		fmt.Fprintln(stderr, "adsshadm:", err)
		return 2
	}
	key, err := loadKey(*keyFile)
	if err != nil {
		fmt.Fprintln(stderr, "adsshadm:", err)
		return 2
	}
	a := &app{c: newClient(ep, key), out: stdout, jsonOut: *jsonOut, yes: *yes, snoop: snoopTerminal}
	interactive := term.IsTerminal(int(os.Stdin.Fd()))
	if interactive {
		a.confirm = lineConfirm(stdin, stderr)
	}
	if fs.NArg() == 0 {
		if !interactive {
			fmt.Fprintln(stderr, "adsshadm: no command given and stdin is not a terminal")
			return 2
		}
		// The prompt makes a fresh signal context per command, so one Ctrl-C
		// ends that command and not the rest of the session.
		if err := a.repl(context.Background()); err != nil {
			fmt.Fprintln(stderr, "adsshadm:", err)
			return 1
		}
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := a.dispatch(ctx, fs.Args()); err != nil {
		fmt.Fprintln(stderr, "adsshadm:", err)
		return 1
	}
	return 0
}

// lineConfirm asks a yes/no question on the terminal for one-shot mode.
func lineConfirm(in io.Reader, out io.Writer) func(string) bool {
	return func(prompt string) bool {
		fmt.Fprintf(out, "%s [y/N] ", prompt)
		var buf [64]byte
		n, _ := in.Read(buf[:])
		ans := strings.ToLower(strings.TrimSpace(string(buf[:n])))
		return ans == "y" || ans == "yes"
	}
}
