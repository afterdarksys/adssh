package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/afterdarksys/adssh/internal/config"
	"github.com/afterdarksys/adssh/internal/sashparent"
)

// runSashEmergency signs purpose emergency and execs sash --session.
// A missing or unusable key prints grant_bad_sig. A missing sash prints
// sash_missing. Neither path falls open to the REPL.
func runSashEmergency(args []string) int {
	seedPath := os.Getenv("ADSSH_SASH_EMERGENCY_SEED")
	if seedPath == "" {
		seedPath = filepath.Join(config.XDGConfigHome(), "sash-emergency.seed")
	}
	fleetPath := os.Getenv("ADSSH_SASH_FLEET_PUB")
	if fleetPath == "" {
		fleetPath = filepath.Join(config.XDGConfigHome(), "sash-fleet.pub")
	}
	seed, fleetPub, err := sashparent.ReadKeyFiles(seedPath, fleetPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 2
	}
	defer sashparent.Zero(seed)
	g, err := sashparent.GrantFromEnv(os.Getenv, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 2
	}
	doc, emerPub, err := sashparent.SignEmergency(g, seed)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 2
	}
	bin, err := exec.LookPath("sash")
	if err != nil {
		fmt.Fprintln(os.Stderr, sashparent.ErrSashMiss.Error())
		return 2
	}
	code, err := sashparent.Run(bin, append([]string{"--session"}, args...), doc, fleetPub, emerPub, os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 2
	}
	return code
}
