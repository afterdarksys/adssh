package parser

import (
	"errors"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

const (
	// MaxChunkBytes is the maximum size of one shell or flow chunk.
	MaxChunkBytes = 1 << 20
	// MaxChunkLines is the maximum number of lines in one chunk.
	MaxChunkLines = 256
)

var (
	ErrIncompleteShell = errors.New("incomplete shell")
	ErrEmptyTry        = errors.New("flow: empty try body")
	ErrEmptyCatch      = errors.New("flow: empty catch body")
	ErrEmptyCond       = errors.New("flow: empty condition")
	ErrEmptyThen       = errors.New("flow: empty then body")
	ErrEmptyElse       = errors.New("flow: empty else body")
	ErrExpectedCatch   = errors.New("flow: expected catch")
	ErrTrailing        = errors.New("flow: trailing input")
	ErrUnclosed        = errors.New("flow: unclosed block")
	ErrTryNeedsCatch   = errors.New("flow: try needs catch")
	ErrTooBig          = errors.New("flow: input exceeds 1 MiB")
	ErrTooManyLines    = errors.New("flow: input exceeds 256 lines")
)

// FlowKind is the classification of a brace if or try/catch chunk.
type FlowKind int

const (
	FlowNot FlowKind = iota
	FlowIncomplete
	FlowSyntax
	FlowReady
)

// Flow is a brace if/else or try/catch form. Bodies exclude the surrounding braces.
type Flow struct {
	Kind    FlowKind
	Err     error
	Op      string
	Cond    string
	Then    string
	Else    string
	HasElse bool
	Try     string
	Catch   string
}

// ChunkKind is the REPL and script decision for one input chunk.
type ChunkKind int

const (
	ChunkReady ChunkKind = iota
	ChunkNeedMore
	ChunkSyntax
)

// Chunk is one classified input chunk.
type Chunk struct {
	Kind ChunkKind
	Err  error
	Mode EvalMode
}

// ClassifyFlow reports whether src is a brace if/else or try/catch form.
// Caps are applied before the scan, including for input that is not a flow form.
// A POSIX if/then/fi and a Starlark `if expr:` are FlowNot.
func ClassifyFlow(src string) Flow {
	if err := checkCap(src); err != nil {
		return Flow{Kind: FlowSyntax, Err: err}
	}
	i := skipWSComments(src, 0)
	word, next, ok := readIdent(src, i)
	if !ok {
		return Flow{Kind: FlowNot}
	}
	switch word {
	case "try":
		return classifyTry(src, next)
	case "if":
		return classifyIf(src, next)
	default:
		return Flow{Kind: FlowNot}
	}
}

// ClassifyChunk reports whether src is ready to run, needs another line, or is rejected.
// Starlark is ready on the first line. The caller keeps reading a Starlark block.
func ClassifyChunk(src string) Chunk {
	flow := ClassifyFlow(src)
	switch flow.Kind {
	case FlowReady:
		return Chunk{Kind: ChunkReady, Mode: ModeShell}
	case FlowIncomplete:
		return Chunk{Kind: ChunkNeedMore, Err: flow.Err, Mode: ModeShell}
	case FlowSyntax:
		return Chunk{Kind: ChunkSyntax, Err: flow.Err}
	}
	first := firstLine(src)
	mode := DetermineMode(first)
	if mode == ModeStarlark {
		return Chunk{Kind: ChunkReady, Mode: ModeStarlark}
	}
	if ShellIncomplete(src) {
		return Chunk{Kind: ChunkNeedMore, Mode: ModeShell}
	}
	return Chunk{Kind: ChunkReady, Mode: ModeShell}
}

// ShellIncomplete reports whether src is an incomplete shell program.
// A hard syntax error is not incomplete. One leading ! or "$ " is stripped.
func ShellIncomplete(src string) bool {
	s := strings.TrimSpace(src)
	if strings.HasPrefix(s, "!") {
		s = strings.TrimSpace(s[1:])
	} else if strings.HasPrefix(s, "$ ") {
		s = strings.TrimSpace(s[2:])
	}
	_, err := syntax.NewParser().Parse(strings.NewReader(s), "")
	return syntax.IsIncomplete(err)
}

func checkCap(src string) error {
	if len(src) > MaxChunkBytes {
		return ErrTooBig
	}
	if chunkLineCount(src) > MaxChunkLines {
		return ErrTooManyLines
	}
	return nil
}

func chunkLineCount(src string) int {
	if src == "" {
		return 0
	}
	n := strings.Count(src, "\n")
	if !strings.HasSuffix(src, "\n") {
		n++
	}
	return n
}

func firstLine(src string) string {
	if i := strings.IndexByte(src, '\n'); i >= 0 {
		return src[:i]
	}
	return src
}

func ifKeyword(trimmed string) bool {
	if strings.HasPrefix(trimmed, "if{") {
		return true
	}
	if strings.HasPrefix(trimmed, "if ") || strings.HasPrefix(trimmed, "if\t") {
		return true
	}
	return false
}

func starlarkIf(src string) bool {
	if firstLineEndsWithColon(src) {
		return true
	}
	_, _, stop := scanCondition(src, len("if"))
	return stop == stopColon
}

func posixIfBeforeBrace(src string) bool {
	_, _, stop := scanCondition(src, len("if"))
	return stop == stopPosix
}

func firstLineEndsWithColon(src string) bool {
	line := src
	if i := strings.IndexByte(src, '\n'); i >= 0 {
		line = src[:i]
	}
	line = strings.TrimRight(stripTrailingComment(line), " \t")
	return strings.HasSuffix(line, ":")
}

func stripTrailingComment(line string) string {
	quote := byte(0)
	escape := false
	for i := 0; i < len(line); i++ {
		b := line[i]
		if quote == '\'' {
			if b == '\'' {
				quote = 0
			}
			continue
		}
		if escape {
			escape = false
			continue
		}
		if quote == '"' {
			if b == '\\' {
				escape = true
				continue
			}
			if b == '"' {
				quote = 0
			}
			continue
		}
		if b == '\\' {
			escape = true
			continue
		}
		if b == '\'' || b == '"' {
			quote = b
			continue
		}
		if b == '#' {
			return line[:i]
		}
	}
	return line
}

type stopKind int

const (
	stopEOF stopKind = iota
	stopBrace
	stopPosix
	stopColon
)

func classifyIf(src string, i int) Flow {
	cond, brace, stop := scanCondition(src, i)
	switch stop {
	case stopPosix, stopColon, stopEOF:
		return Flow{Kind: FlowNot}
	case stopBrace:
	default:
		return Flow{Kind: FlowNot}
	}
	if strings.TrimSpace(stripComments(cond)) == "" {
		return Flow{Kind: FlowSyntax, Err: ErrEmptyCond}
	}
	body, next, saw, incomplete := scanBlock(src, brace)
	if incomplete {
		return Flow{Kind: FlowIncomplete, Err: ErrUnclosed}
	}
	if !saw {
		return Flow{Kind: FlowSyntax, Err: ErrEmptyThen}
	}
	j := skipWSComments(src, next)
	if j >= len(src) {
		return Flow{Kind: FlowReady, Op: "if", Cond: cond, Then: body}
	}
	word, after, ok := readIdent(src, j)
	if !ok || word != "else" {
		return Flow{Kind: FlowSyntax, Err: ErrTrailing}
	}
	k := skipWSComments(src, after)
	if k >= len(src) {
		return Flow{Kind: FlowIncomplete, Err: ErrUnclosed}
	}
	if src[k] != '{' {
		return Flow{Kind: FlowSyntax, Err: ErrTrailing}
	}
	elseBody, rest, elseSaw, elseInc := scanBlock(src, k)
	if elseInc {
		return Flow{Kind: FlowIncomplete, Err: ErrUnclosed}
	}
	if !elseSaw {
		return Flow{Kind: FlowSyntax, Err: ErrEmptyElse}
	}
	if skipWSComments(src, rest) < len(src) {
		return Flow{Kind: FlowSyntax, Err: ErrTrailing}
	}
	return Flow{Kind: FlowReady, Op: "if", Cond: cond, Then: body, Else: elseBody, HasElse: true}
}

func classifyTry(src string, i int) Flow {
	j := skipWSComments(src, i)
	if j >= len(src) || src[j] != '{' {
		return Flow{Kind: FlowNot}
	}
	body, next, saw, incomplete := scanBlock(src, j)
	if incomplete {
		return Flow{Kind: FlowIncomplete, Err: ErrUnclosed}
	}
	if !saw {
		return Flow{Kind: FlowSyntax, Err: ErrEmptyTry}
	}
	k := skipWSComments(src, next)
	if k >= len(src) {
		return Flow{Kind: FlowIncomplete, Err: ErrTryNeedsCatch}
	}
	word, after, ok := readIdent(src, k)
	if !ok || word != "catch" {
		return Flow{Kind: FlowSyntax, Err: ErrExpectedCatch}
	}
	c := skipWSComments(src, after)
	if c >= len(src) {
		return Flow{Kind: FlowIncomplete, Err: ErrUnclosed}
	}
	if src[c] != '{' {
		return Flow{Kind: FlowSyntax, Err: ErrExpectedCatch}
	}
	catchBody, rest, catchSaw, catchInc := scanBlock(src, c)
	if catchInc {
		return Flow{Kind: FlowIncomplete, Err: ErrUnclosed}
	}
	if !catchSaw {
		return Flow{Kind: FlowSyntax, Err: ErrEmptyCatch}
	}
	if skipWSComments(src, rest) < len(src) {
		return Flow{Kind: FlowSyntax, Err: ErrTrailing}
	}
	return Flow{Kind: FlowReady, Op: "try", Try: body, Catch: catchBody}
}

// scanCondition scans the shell command between if and the then-body brace.
// i is the index just after the if keyword. ${...} counts toward depth.
// A word then or fi, or a colon outside quotes, stops the scan as not-a-brace-form.
func scanCondition(src string, i int) (cond string, brace int, stop stopKind) {
	start := i
	quote := byte(0)
	escape := false
	comment := false
	depth := 0
	var word []byte
	flush := func() bool {
		w := string(word)
		word = word[:0]
		return w == "then" || w == "fi"
	}
	for i < len(src) {
		b := src[i]
		if comment {
			if b == '\n' {
				comment = false
			}
			i++
			continue
		}
		if quote == '\'' {
			if b == '\'' {
				quote = 0
			}
			i++
			continue
		}
		if escape {
			escape = false
			i++
			continue
		}
		if quote == '"' {
			if b == '\\' {
				escape = true
				i++
				continue
			}
			if b == '"' {
				quote = 0
			}
			i++
			continue
		}
		if depth > 0 {
			if b == '\\' {
				escape = true
				i++
				continue
			}
			if b == '\'' || b == '"' {
				quote = b
				i++
				continue
			}
			if b == '{' {
				depth++
			} else if b == '}' {
				depth--
			}
			i++
			continue
		}
		if b == '\\' {
			if flush() {
				return "", 0, stopPosix
			}
			escape = true
			i++
			continue
		}
		if b == '\'' || b == '"' {
			if flush() {
				return "", 0, stopPosix
			}
			quote = b
			i++
			continue
		}
		if b == '#' {
			if flush() {
				return "", 0, stopPosix
			}
			comment = true
			i++
			continue
		}
		if b == '$' && i+1 < len(src) && src[i+1] == '{' {
			if flush() {
				return "", 0, stopPosix
			}
			depth = 1
			i += 2
			continue
		}
		if b == ':' {
			if flush() {
				return "", 0, stopPosix
			}
			return "", 0, stopColon
		}
		if b == '{' {
			if flush() {
				return "", 0, stopPosix
			}
			return src[start:i], i, stopBrace
		}
		if isWordSep(b) {
			if flush() {
				return "", 0, stopPosix
			}
			i++
			continue
		}
		word = append(word, b)
		i++
	}
	if flush() {
		return "", 0, stopPosix
	}
	if quote != 0 || depth > 0 || escape {
		return "", 0, stopEOF
	}
	return "", 0, stopEOF
}

func isWordSep(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', ';', '|', '&', '(', ')', '<', '>':
		return true
	default:
		return false
	}
}

// scanBlock scans a brace body. open is the index of the opening brace.
// Nested braces and ${...} count toward depth. Braces in quotes do not.
func scanBlock(src string, open int) (body string, next int, sawCode, incomplete bool) {
	if open >= len(src) || src[open] != '{' {
		return "", open, false, true
	}
	i := open + 1
	start := i
	depth := 1
	quote := byte(0)
	escape := false
	comment := false
	for i < len(src) {
		b := src[i]
		if comment {
			if b == '\n' {
				comment = false
			}
			i++
			continue
		}
		if quote == '\'' {
			if b == '\'' {
				quote = 0
			} else if !isSpace(b) {
				sawCode = true
			}
			i++
			continue
		}
		if escape {
			escape = false
			if b != '\n' && b != '\r' {
				sawCode = true
			}
			i++
			continue
		}
		if quote == '"' {
			if b == '\\' {
				escape = true
				i++
				continue
			}
			if b == '"' {
				quote = 0
				i++
				continue
			}
			if !isSpace(b) {
				sawCode = true
			}
			i++
			continue
		}
		if b == '\\' {
			escape = true
			i++
			continue
		}
		if b == '\'' || b == '"' {
			quote = b
			i++
			continue
		}
		if b == '#' {
			comment = true
			i++
			continue
		}
		if b == '{' {
			depth++
			sawCode = true
			i++
			continue
		}
		if b == '}' {
			depth--
			if depth == 0 {
				return src[start:i], i + 1, sawCode, false
			}
			sawCode = true
			i++
			continue
		}
		if !isSpace(b) {
			sawCode = true
		}
		i++
	}
	return "", len(src), sawCode, true
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func skipWSComments(src string, i int) int {
	for i < len(src) {
		if isSpace(src[i]) {
			i++
			continue
		}
		if src[i] == '#' {
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		}
		break
	}
	return i
}

func stripComments(src string) string {
	var b strings.Builder
	quote := byte(0)
	escape := false
	comment := false
	for i := 0; i < len(src); i++ {
		c := src[i]
		if comment {
			if c == '\n' {
				comment = false
				b.WriteByte(c)
			}
			continue
		}
		if quote == '\'' {
			b.WriteByte(c)
			if c == '\'' {
				quote = 0
			}
			continue
		}
		if escape {
			escape = false
			b.WriteByte(c)
			continue
		}
		if quote == '"' {
			b.WriteByte(c)
			if c == '\\' {
				escape = true
				continue
			}
			if c == '"' {
				quote = 0
			}
			continue
		}
		if c == '\\' {
			escape = true
			b.WriteByte(c)
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			b.WriteByte(c)
			continue
		}
		if c == '#' {
			comment = true
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func readIdent(src string, i int) (string, int, bool) {
	if i >= len(src) || !isIdentStart(src[i]) {
		return "", i, false
	}
	j := i + 1
	for j < len(src) && isIdentCont(src[j]) {
		j++
	}
	return src[i:j], j, true
}

func isIdentStart(b byte) bool {
	return b == '_' || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func isIdentCont(b byte) bool {
	return isIdentStart(b) || (b >= '0' && b <= '9')
}
