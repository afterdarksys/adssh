//go:build ee

package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/afterdarksys/adssh/security"
)

// asofVerifyArgs handles `adssh asof --chain PATH --key PATH --seq N` before
// the flag loop, which would otherwise treat asof as a script path.
func asofVerifyArgs() (int, bool) {
	var rest []string
	saw := false
	for _, arg := range os.Args[1:] {
		if arg == "--" {
			break
		}
		if !saw {
			if arg == "asof" {
				saw = true
			}
			continue
		}
		rest = append(rest, arg)
	}
	if !saw {
		return 0, false
	}
	chain, key, seq, err := parseAsofCLI(rest)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 2, true
	}
	text, err := security.AsofAt(chain, key, seq)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 2, true
	}
	fmt.Fprint(os.Stdout, text)
	return 0, true
}

func parseAsofCLI(args []string) (chain, key string, seq int64, err error) {
	usage := fmt.Errorf("asof: usage: asof --chain PATH --key PATH --seq N")
	var gotChain, gotKey, gotSeq bool
	for i := 0; i < len(args); i++ {
		flag := args[i]
		if flag != "--chain" && flag != "--key" && flag != "--seq" {
			return "", "", 0, usage
		}
		if i+1 >= len(args) {
			return "", "", 0, usage
		}
		val := args[i+1]
		i++
		switch flag {
		case "--chain":
			if gotChain || val == "" {
				return "", "", 0, usage
			}
			gotChain, chain = true, val
		case "--key":
			if gotKey || val == "" {
				return "", "", 0, usage
			}
			gotKey, key = true, val
		case "--seq":
			if gotSeq {
				return "", "", 0, usage
			}
			n, nerr := strconv.ParseInt(val, 10, 64)
			if nerr != nil || n < 0 {
				return "", "", 0, usage
			}
			gotSeq, seq = true, n
		}
	}
	if !gotChain || !gotKey || !gotSeq {
		return "", "", 0, usage
	}
	return chain, key, seq, nil
}

func runRecover(sec *security.Engine, sessionID string) int {
	code, err := security.RunRecovery(context.Background(), sec, sessionID, os.Stdin, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "adssh: %v\n", err)
	}
	return code
}
