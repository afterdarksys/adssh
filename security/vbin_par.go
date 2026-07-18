package security

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"sync"

	"mvdan.cc/sh/v3/interp"
)

type parBinary struct{}

func (parBinary) Name() string { return "par" }
func (parBinary) Description() string {
	return "Run an argv template across items with bounded parallelism and per-child governance"
}
func (parBinary) Usage() string {
	return "par [--jobs N] [items...] -- command [args containing {}]"
}

type parResult struct {
	item   string
	result commandResult
	err    error
}

func (parBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	jobs := 4
	delimiter := -1
	var items []string
	for i := 1; i < len(args); i++ {
		if args[i] == "--" {
			delimiter = i
			break
		}
		if args[i] == "--jobs" || args[i] == "-j" {
			if i+1 >= len(args) {
				return fmt.Errorf("par: --jobs requires a value")
			}
			i++
			var err error
			if _, err = fmt.Sscanf(args[i], "%d", &jobs); err != nil || jobs < 1 || jobs > 64 {
				return fmt.Errorf("par: jobs must be between 1 and 64")
			}
			continue
		}
		if strings.HasPrefix(args[i], "-") {
			return fmt.Errorf("par: unknown option %q", args[i])
		}
		items = append(items, args[i])
	}
	if delimiter < 0 || delimiter+1 >= len(args) {
		return fmt.Errorf("par: usage: %s", parBinary{}.Usage())
	}
	template := append([]string(nil), args[delimiter+1:]...)
	if len(items) == 0 {
		scanner := bufio.NewScanner(hc.Stdin)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			if len(items) >= 10000 {
				return fmt.Errorf("par: item limit 10000 exceeded")
			}
			items = append(items, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("par: read items: %w", err)
		}
	}
	if len(items) == 0 {
		return fmt.Errorf("par: no items supplied")
	}
	engine := engineFromContext(ctx)
	if _, isVBin := engine.Lookup(template[0]); isVBin && jobs > 1 {
		return fmt.Errorf("par: virtual binary children require --jobs 1 because they share terminal state")
	}
	if jobs > len(items) {
		jobs = len(items)
	}

	results := make([]parResult, len(items))
	indices := make(chan int)
	var workers sync.WaitGroup
	for worker := 0; worker < jobs; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range indices {
				item := items[index]
				command := substituteParItem(template, item)
				result, err := engine.runGovernedCommand(ctx, SessionIDFromContext(ctx), governedCommand{
					Args: command,
					Dir:  hc.Dir,
				}, nil)
				if err == nil && result.ExitCode != 0 {
					err = fmt.Errorf("exited with status %d", result.ExitCode)
				}
				results[index] = parResult{item: item, result: result, err: err}
			}
		}()
	}
	for index := range items {
		select {
		case indices <- index:
		case <-ctx.Done():
			close(indices)
			workers.Wait()
			return ctx.Err()
		}
	}
	close(indices)
	workers.Wait()

	var firstErr error
	for _, itemResult := range results {
		if len(itemResult.result.Stdout) > 0 {
			_, _ = hc.Stdout.Write(itemResult.result.Stdout)
		}
		if len(itemResult.result.Stderr) > 0 {
			_, _ = hc.Stderr.Write(itemResult.result.Stderr)
		}
		if itemResult.err != nil && firstErr == nil {
			firstErr = fmt.Errorf("par: item %q: %w", itemResult.item, itemResult.err)
		}
	}
	return firstErr
}

func substituteParItem(template []string, item string) []string {
	command := make([]string, len(template))
	replaced := false
	for index, arg := range template {
		if strings.Contains(arg, "{}") {
			arg = strings.ReplaceAll(arg, "{}", item)
			replaced = true
		}
		command[index] = arg
	}
	if !replaced {
		command = append(command, item)
	}
	return command
}
