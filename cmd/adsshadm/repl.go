package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chzyer/readline"
)

const completionTimeout = 2 * time.Second

// repl runs the adsshadm> prompt until exit, quit, or EOF.
func (a *app) repl(ctx context.Context) error {
	cfg := &readline.Config{
		Prompt:            "adsshadm> ",
		AutoComplete:      &completer{a: a, ctx: ctx},
		InterruptPrompt:   "^C",
		EOFPrompt:         "exit",
		HistorySearchFold: true,
	}
	if dir, err := os.UserHomeDir(); err == nil {
		cfg.HistoryFile = filepath.Join(dir, ".adssh", "adsshadm_history")
	}
	rl, err := readline.NewEx(cfg)
	if err != nil {
		return err
	}
	defer rl.Close()
	a.out = rl.Stdout()
	a.confirm = readlineConfirm(rl)
	fmt.Fprintln(a.out, "adsshadm: connected to the adssh admin API. help lists commands; exit leaves.")
	for {
		line, err := rl.Readline()
		if errors.Is(err, readline.ErrInterrupt) {
			continue
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		words, err := splitWords(line)
		if err != nil {
			fmt.Fprintln(a.out, "adsshadm:", err)
			continue
		}
		if len(words) == 0 {
			continue
		}
		if words[0] == "exit" || words[0] == "quit" {
			return nil
		}
		if err := a.dispatch(ctx, words); err != nil {
			fmt.Fprintln(a.out, "adsshadm:", err)
		}
	}
}

func readlineConfirm(rl *readline.Instance) func(string) bool {
	return func(prompt string) bool {
		old := rl.Config.Prompt
		rl.SetPrompt(prompt + " [y/N] ")
		defer rl.SetPrompt(old)
		ans, err := rl.Readline()
		if err != nil {
			return false
		}
		ans = strings.ToLower(strings.TrimSpace(ans))
		return ans == "y" || ans == "yes"
	}
}

// completer completes command names, then live values from the admin API.
type completer struct {
	a   *app
	ctx context.Context
}

func (c *completer) Do(line []rune, pos int) ([][]rune, int) {
	head := string(line[:pos])
	cut := strings.LastIndexAny(head, " \t")
	partial := head[cut+1:]
	// Completing inside quotes or escapes would replace the wrong span.
	if strings.ContainsAny(partial, `"'\`) {
		return nil, 0
	}
	words, err := splitWords(head[:cut+1])
	if err != nil {
		return nil, 0
	}
	var candidates []string
	if len(words) == 0 {
		for _, cmd := range commands() {
			candidates = append(candidates, cmd.name)
		}
		candidates = append(candidates, "help", "exit")
	} else if cmd, ok := findCommand(words[0]); ok && cmd.suggest != nil {
		ctx, cancel := context.WithTimeout(c.ctx, completionTimeout)
		defer cancel()
		candidates = cmd.suggest(ctx, c.a, len(words)-1)
	}
	var out [][]rune
	for _, cand := range candidates {
		// Server values are user-typed; never insert one that could carry
		// a control sequence or split into several words.
		if strings.IndexFunc(cand, unsafeRune) >= 0 || strings.ContainsAny(cand, " \t\"'\\") {
			continue
		}
		if strings.HasPrefix(cand, partial) {
			out = append(out, []rune(cand[len(partial):]+" "))
		}
	}
	return out, len([]rune(partial))
}

// splitWords splits a line like a shell would for plain words, single and
// double quotes, and backslash escapes. It does no expansion.
func splitWords(line string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord := false
	var quote rune
	escaped := false
	for _, r := range line {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case quote != 0:
			if r == quote {
				quote = 0
			} else if r == '\\' && quote == '"' {
				escaped = true
			} else {
				cur.WriteRune(r)
			}
		case r == '\\':
			escaped, inWord = true, true
		case r == '"' || r == '\'':
			quote, inWord = r, true
		case r == ' ' || r == '\t':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	if escaped {
		return nil, errors.New("trailing backslash")
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}
