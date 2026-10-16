package starlarkext

// Text helpers in the `str` namespace: str.slugify and str.template.
//
// Both are pure and classified into the existing `strings` capability group,
// so they stay available in restricted sessions.
//
// str.template cannot call out. It runs Go text/template with:
//   - only the built-in comparison/logic/printf set (eq ne lt le gt ge and or
//     not len index slice print printf println); call, html, js and urlquery
//     are replaced by functions that fail;
//   - vars converted to plain maps, lists, strings, numbers and bools, so no
//     Go method or function value is reachable from the data;
//   - no file loading: the template is parsed per call from the string, and
//     {{template "x"}} of a name not defined in that string fails.
//
// Threats:
//   - Calling out of a template. See above; no function can do I/O.
//   - Memory exhaustion. Template text, converted vars and output are each
//     capped at 1 MiB; output past the cap fails the call.
//   - CPU exhaustion. A range whose pipeline is not a field, variable, dot
//     or chain of those is refused at parse time, so {{range 5}},
//     {{range (5)}} and {{range or 0 5}} never run. Every range pipeline and
//     every {{template}} call is then rewritten to pass through a guard
//     function. The guard refuses to range over any integer (one held in a
//     variable, in dot after {{with 5}}, or taken from vars) and fails once
//     the call's deadline has passed. Loops and recursion can only repeat
//     work through range or template, so a timed-out worker reaches a guard
//     and stops within one innermost range: at most one pass over a list or
//     map from vars, which the 1 MiB vars cap bounds. Writes also fail after
//     the deadline. Execution runs under templateDeadline and fails closed.
//     Residual: the worker outlives the call by that one innermost pass.
//   - Silent typos. strict=True (the default) sets missingkey=error.
// It does not escape output for HTML, shell or any other target language.

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"text/template"
	"text/template/parse"
	"time"
	"unicode"
	"unicode/utf8"

	"go.starlark.net/starlark"
	"golang.org/x/text/unicode/norm"
)

const (
	maxTemplateBytes = 1 << 20
	maxSlugMax       = 1024
	maxSlugSepRunes  = 8
)

// templateDeadline bounds template execution. A var so tests can shorten it.
var templateDeadline = 2 * time.Second

// str.slugify(s, sep="-", max=80) -> string. Lowercases, decomposes (NFKD),
// drops combining marks, keeps runs of Unicode letters and digits as words
// and joins them with sep. Whole words are kept while the result fits in max
// runes; a first word longer than max is cut. The result never starts or
// ends with sep.
func strSlugify(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s string
	sep := "-"
	limit := 80
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "s", &s, "sep?", &sep, "max?", &limit); err != nil {
		return nil, err
	}
	if limit < 1 || limit > maxSlugMax {
		return nil, fmt.Errorf("str.slugify: max must be between 1 and %d", maxSlugMax)
	}
	if utf8.RuneCountInString(sep) > maxSlugSepRunes {
		return nil, fmt.Errorf("str.slugify: sep is longer than %d characters", maxSlugSepRunes)
	}
	decomposed := norm.NFKD.String(strings.ToLower(s))
	var words []string
	var word []rune
	for _, r := range decomposed {
		switch {
		case unicode.Is(unicode.Mn, r):
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			word = append(word, unicode.ToLower(r))
		case len(word) > 0:
			words = append(words, string(word))
			word = word[:0]
		}
	}
	if len(word) > 0 {
		words = append(words, string(word))
	}
	// Keep whole words while they fit; a first word longer than max is cut.
	var slug strings.Builder
	used := 0
	sepLen := utf8.RuneCountInString(sep)
	for i, w := range words {
		n := utf8.RuneCountInString(w)
		if i == 0 {
			if n > limit {
				w = string([]rune(w)[:limit])
				n = limit
			}
			slug.WriteString(w)
			used = n
			continue
		}
		if used+sepLen+n > limit {
			break
		}
		slug.WriteString(sep)
		slug.WriteString(w)
		used += sepLen + n
	}
	return starlark.String(slug.String()), nil
}

// disabledTemplateFuncs replaces the text/template builtins outside the
// comparison/printf set. Funcs entries take precedence over builtins.
var disabledTemplateFuncs = func() template.FuncMap {
	m := template.FuncMap{}
	for _, name := range []string{"call", "html", "js", "urlquery"} {
		name := name
		m[name] = func(...any) (string, error) {
			return "", fmt.Errorf("%s is disabled in str.template", name)
		}
	}
	return m
}()

// str.template(tmpl, vars={}, strict=True) -> string.
func strTemplate(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var tmpl string
	var vars starlark.Value = starlark.NewDict(0)
	strict := true
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "tmpl", &tmpl, "vars?", &vars, "strict?", &strict); err != nil {
		return nil, err
	}
	if len(tmpl) > maxTemplateBytes {
		return nil, fmt.Errorf("str.template: template exceeds %d bytes", maxTemplateBytes)
	}
	switch vars.(type) {
	case *starlark.Dict, *GovernedStarlarkDict:
	default:
		return nil, fmt.Errorf("str.template: vars must be a dict, got %s", vars.Type())
	}
	data, err := toJSONValue(vars, false)
	if err != nil {
		return nil, fmt.Errorf("str.template: vars: %w", err)
	}

	out := &templateBuffer{limit: maxTemplateBytes}
	t := template.New("str.template").Funcs(disabledTemplateFuncs).Funcs(templateGuards(out, time.Now().Add(templateDeadline)))
	if strict {
		t = t.Option("missingkey=error")
	} else {
		t = t.Option("missingkey=default")
	}
	parsed, err := t.Parse(tmpl)
	if err != nil {
		return nil, fmt.Errorf("str.template: parse: %v", err)
	}
	for _, defined := range parsed.Templates() {
		if defined.Tree == nil {
			continue
		}
		if err := guardTemplateNode(defined.Root); err != nil {
			return nil, fmt.Errorf("str.template: %w", err)
		}
	}

	err = runBounded(templateDeadline, func() error {
		return parsed.Execute(out, data)
	})
	if err != nil {
		out.stop()
		if errors.Is(err, errTemplateOutput) {
			return nil, fmt.Errorf("str.template: output exceeds %d bytes", maxTemplateBytes)
		}
		if errors.Is(err, errTemplateStopped) {
			return nil, fmt.Errorf("str.template: exceeded the %s time limit (fail-closed)", templateDeadline)
		}
		return nil, fmt.Errorf("str.template: %w", err)
	}
	return starlark.String(out.buf.String()), nil
}

var (
	errTemplateOutput  = errors.New("template output limit")
	errTemplateStopped = errors.New("template stopped")
)

// templateBuffer caps output and fails every write after stop.
type templateBuffer struct {
	buf     bytes.Buffer
	limit   int
	stopped atomic.Bool
}

func (w *templateBuffer) Write(p []byte) (int, error) {
	if w.stopped.Load() {
		return 0, errTemplateStopped
	}
	if w.buf.Len()+len(p) > w.limit {
		return 0, errTemplateOutput
	}
	return w.buf.Write(p)
}

func (w *templateBuffer) stop() { w.stopped.Store(true) }

// Names of the guard functions guardTemplateNode inserts. They are ordinary
// template functions; calling them directly does nothing harmful.
const (
	templateRangeGuard = "__adssh_range"
	templateCallGuard  = "__adssh_call"
)

// templateGuards returns the guard functions for one str.template call. Both
// fail once the deadline has passed or the call has been stopped.
func templateGuards(out *templateBuffer, deadline time.Time) template.FuncMap {
	live := func() error {
		if out.stopped.Load() || time.Now().After(deadline) {
			return errTemplateStopped
		}
		return nil
	}
	return template.FuncMap{
		templateRangeGuard: func(v any) (any, error) {
			if err := live(); err != nil {
				return nil, err
			}
			switch reflect.ValueOf(v).Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
				reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
				reflect.Func:
				return nil, errors.New("range over a number is refused")
			}
			return v, nil
		},
		templateCallGuard: func(v ...any) (any, error) {
			if err := live(); err != nil {
				return nil, err
			}
			if len(v) == 0 {
				return nil, nil
			}
			return v[0], nil
		},
	}
}

// guardTemplateNode refuses a range whose pipeline is not a single field,
// variable, dot or chain of those, and appends a guard command to every range
// pipeline and template call in the tree.
func guardTemplateNode(node parse.Node) error {
	switch n := node.(type) {
	case *parse.ListNode:
		if n == nil {
			return nil
		}
		for _, child := range n.Nodes {
			if err := guardTemplateNode(child); err != nil {
				return err
			}
		}
	case *parse.RangeNode:
		if !rangeableSource(n.Pipe) {
			return fmt.Errorf("range is allowed only over a field, variable or dot (range over a number is refused): %s", n.Pipe)
		}
		n.Pipe.Cmds = append(n.Pipe.Cmds, guardCommand(templateRangeGuard, n.Pipe.Pos))
		if err := guardTemplateNode(n.List); err != nil {
			return err
		}
		return guardTemplateNode(n.ElseList)
	case *parse.TemplateNode:
		if n.Pipe == nil {
			n.Pipe = &parse.PipeNode{NodeType: parse.NodePipe, Pos: n.Pos, Line: n.Line}
		}
		n.Pipe.Cmds = append(n.Pipe.Cmds, guardCommand(templateCallGuard, n.Pipe.Pos))
	case *parse.IfNode:
		if err := guardTemplateNode(n.List); err != nil {
			return err
		}
		return guardTemplateNode(n.ElseList)
	case *parse.WithNode:
		if err := guardTemplateNode(n.List); err != nil {
			return err
		}
		return guardTemplateNode(n.ElseList)
	}
	return nil
}

// rangeableSource reports whether a range pipeline is one command holding
// one field, variable, dot or chain of those.
func rangeableSource(pipe *parse.PipeNode) bool {
	if pipe == nil || len(pipe.Cmds) != 1 || len(pipe.Cmds[0].Args) != 1 {
		return false
	}
	return dataReference(pipe.Cmds[0].Args[0])
}

func dataReference(node parse.Node) bool {
	switch n := node.(type) {
	case *parse.FieldNode, *parse.VariableNode, *parse.DotNode:
		return true
	case *parse.ChainNode:
		return dataReference(n.Node)
	}
	return false
}

// guardCommand builds the pipeline stage "| name". In a pipeline the previous
// stage's value is passed as the last argument; a pipeline of only this stage
// calls it with none.
func guardCommand(name string, pos parse.Pos) *parse.CommandNode {
	return &parse.CommandNode{
		NodeType: parse.NodeCommand,
		Pos:      pos,
		Args:     []parse.Node{parse.NewIdentifier(name).SetPos(pos)},
	}
}
