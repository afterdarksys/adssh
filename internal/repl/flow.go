package repl

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/afterdarksys/adssh/parser"
	"github.com/chzyer/readline"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// Threats: brace if/else and try/catch are an execution path. Each body is
// parsed and passed through the caller-supplied Gate before any statement
// runs. A syntax error, an empty body, or a gate error runs nothing. Only a
// direct non-zero interp.ExitStatus is catchable. A policy denial, a
// restricted-mode rejection, or any other runner error is returned and does
// not enter catch or else. Incomplete, oversized, or still-open input is not
// executed.

// FlowExec runs one brace if/else or try/catch chunk.
// Gate is the session program gate. Runner is the session shell runner.
type FlowExec struct {
	Gate   func(syntax.Node) error
	Runner *interp.Runner
	Ctx    context.Context
}

// RunFlow runs a ready brace if/else or try/catch chunk.
// A non-zero exit status from the chosen branch is returned as interp.ExitStatus.
// A denial or a syntax error is returned and does not enter catch or else.
func RunFlow(src string, ex FlowExec) error {
	if ex.Ctx == nil {
		ex.Ctx = context.Background()
	}
	if err := ex.Ctx.Err(); err != nil {
		return err
	}
	flow := parser.ClassifyFlow(src)
	if flow.Kind != parser.FlowReady {
		if flow.Err != nil {
			return flow.Err
		}
		return errors.New("flow: not a block")
	}
	if ex.Gate == nil || ex.Runner == nil {
		return errors.New("flow: runner is not configured")
	}
	switch flow.Op {
	case "try":
		tryFile, catchFile, err := preparePair("try", flow.Try, "catch", flow.Catch, ex.Gate)
		if err != nil {
			return err
		}
		err = runStmts(ex.Ctx, ex.Runner, tryFile)
		if err == nil {
			return nil
		}
		if _, ok := err.(interp.ExitStatus); !ok {
			return err
		}
		return runStmts(ex.Ctx, ex.Runner, catchFile)
	case "if":
		condFile, err := prepareBody("condition", flow.Cond, ex.Gate)
		if err != nil {
			return err
		}
		thenFile, err := prepareBody("then", flow.Then, ex.Gate)
		if err != nil {
			return err
		}
		var elseFile *syntax.File
		if flow.HasElse {
			elseFile, err = prepareBody("else", flow.Else, ex.Gate)
			if err != nil {
				return err
			}
		}
		err = runStmts(ex.Ctx, ex.Runner, condFile)
		if err != nil {
			if _, ok := err.(interp.ExitStatus); !ok {
				return err
			}
			if !flow.HasElse {
				return nil
			}
			return runStmts(ex.Ctx, ex.Runner, elseFile)
		}
		return runStmts(ex.Ctx, ex.Runner, thenFile)
	default:
		return errors.New("flow: not a block")
	}
}

func preparePair(aName, aSrc, bName, bSrc string, gate func(syntax.Node) error) (*syntax.File, *syntax.File, error) {
	a, err := prepareBody(aName, aSrc, gate)
	if err != nil {
		return nil, nil, err
	}
	b, err := prepareBody(bName, bSrc, gate)
	if err != nil {
		return nil, nil, err
	}
	return a, b, nil
}

func prepareBody(name, src string, gate func(syntax.Node) error) (*syntax.File, error) {
	f, err := syntax.NewParser().Parse(strings.NewReader(src), name)
	if err != nil {
		return nil, err
	}
	if f == nil || len(f.Stmts) == 0 {
		return nil, emptyBody(name)
	}
	if err := gate(f); err != nil {
		return nil, err
	}
	return f, nil
}

func emptyBody(name string) error {
	switch name {
	case "try":
		return parser.ErrEmptyTry
	case "catch":
		return parser.ErrEmptyCatch
	case "condition":
		return parser.ErrEmptyCond
	case "then":
		return parser.ErrEmptyThen
	case "else":
		return parser.ErrEmptyElse
	default:
		return fmt.Errorf("flow: empty %s body", name)
	}
}

// runStmts runs each statement on its own and stops on a non-zero exit status.
// Any other runner error is returned unchanged. A whole-file run would keep
// going after false when set -e is off, and would hide a denial inside ExitStatus.
func runStmts(ctx context.Context, runner *interp.Runner, f *syntax.File) error {
	for _, stmt := range f.Stmts {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := runner.Run(ctx, stmt)
		if err == nil {
			continue
		}
		status, ok := err.(interp.ExitStatus)
		if !ok {
			return err
		}
		if status != 0 {
			return err
		}
	}
	return nil
}

// AccumulateScript splits a .adssh script into shell, Starlark, and flow chunks.
// Blanks and comments are skipped only while no chunk is open. exit and quit end
// the script only when no chunk is open. A leading "-" on the first line of a
// chunk sets ignore. An incomplete chunk at EOF is returned and is not executed.
func AccumulateScript(src string, exec func(chunk string, line int, ignore bool) error) error {
	sc := bufio.NewScanner(strings.NewReader(src))
	sc.Buffer(make([]byte, 64*1024), parser.MaxChunkBytes+1)
	var pending strings.Builder
	var startLine int
	ignore := false
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		if pending.Len() == 0 {
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if trimmed == "exit" || trimmed == "quit" {
				return nil
			}
			ignore = false
			if strings.HasPrefix(trimmed, "-") {
				ignore = true
				trimmed = strings.TrimSpace(trimmed[1:])
			}
			pending.WriteString(trimmed)
			startLine = lineNo
		} else {
			pending.WriteByte('\n')
			pending.WriteString(raw)
		}
		switch parser.ClassifyChunk(pending.String()).Kind {
		case parser.ChunkNeedMore:
			continue
		default:
			chunk := pending.String()
			pending.Reset()
			chunkIgnore := ignore
			ignore = false
			if err := exec(chunk, startLine, chunkIgnore); err != nil {
				return err
			}
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return fmt.Errorf("line %d: %w", lineNo+1, parser.ErrTooBig)
		}
		return err
	}
	if pending.Len() > 0 {
		err := parser.ClassifyChunk(pending.String()).Err
		if err == nil {
			err = parser.ErrUnclosed
		}
		return fmt.Errorf("line %d: %w", startLine, err)
	}
	return nil
}

// readPending reads continuation lines until the chunk is ready or rejected.
// Blank lines stay in the chunk. exit inside the chunk does not leave the shell.
func readPending(rl *readline.Instance, line, prompt string, out io.Writer) (buf string, abort, eof bool, synErr error) {
	defer rl.SetPrompt(prompt)
	buf = line
	for {
		chunk := parser.ClassifyChunk(buf)
		switch chunk.Kind {
		case parser.ChunkSyntax:
			return "", false, false, chunk.Err
		case parser.ChunkNeedMore:
			rl.SetPrompt("...   ")
			next, err := rl.Readline()
			if err == readline.ErrInterrupt {
				fmt.Fprintln(out)
				return "", true, false, nil
			}
			if err == io.EOF {
				return "", false, true, nil
			}
			if err != nil {
				return "", true, false, nil
			}
			buf += "\n" + next
		default:
			return buf, false, false, nil
		}
	}
}
