package starlarkext

// Config/data helpers in the `data` namespace: data.assert_type and
// data.validate (JSON Schema, draft 2020-12 by default).
//
// Both are pure: no file, network, process, clock-dependent result or
// package-level mutable state is touched while computing a result. They are
// classified into the existing `data` capability group and stay available in
// restricted sessions.
//
// Threats:
//   - Schema-driven I/O. A JSON Schema `$ref` can name an http(s) or file URL.
//     The compiler's URL loader is replaced with one that refuses every load,
//     so any reference outside the schema document fails closed with
//     "external $ref refused". Only the metaschemas embedded in the library
//     resolve without the loader. The schema is registered under a mem:///
//     URL, so a relative $ref never resolves against the working directory.
//   - Oversized input. A schema string and the converted schema/document are
//     each capped at maxValidateBytes; container nesting is capped at
//     maxValidateDepth, which also stops a self-referencing list.
//   - Slow compile or validate. Work runs under a validateDeadline context; on
//     expiry the call fails closed. The library has no cancellation hook, so
//     the worker goroutine finishes in the background, bounded by the input
//     caps. RE2 regexps keep pattern matching linear.
//   - Lossy conversion. Non-string dict keys, NaN/Inf floats and values with no
//     JSON form are rejected instead of being stringified.
// It does not decide whether a schema is sensible; it only evaluates it.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.starlark.net/starlark"
	"gopkg.in/yaml.v3"
)

const (
	maxValidateBytes = 1 << 20
	maxValidateDepth = 128
	schemaResource   = "mem:///schema.json"
)

var (
	// validateDeadline bounds compile+validate. A var so tests can shorten it.
	validateDeadline = 2 * time.Second
	// boundedHook, when set by a test, runs at the start of every bounded
	// worker. It is nil in production.
	boundedHook func()

	errExternalRef = errors.New("external $ref refused: data.validate does not load remote or file schemas")
)

// data.assert_type(value, expected) -> value. expected is a Starlark type
// name or a list/tuple of names.
func dataAssertType(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value, expected starlark.Value
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "value", &value, "expected", &expected); err != nil {
		return nil, err
	}
	var names []string
	switch exp := expected.(type) {
	case starlark.String:
		names = []string{string(exp)}
	case starlark.Indexable:
		for i := 0; i < exp.Len(); i++ {
			name, ok := starlark.AsString(exp.Index(i))
			if !ok {
				return nil, fmt.Errorf("data.assert_type: expected must be a type name or a list of type names")
			}
			names = append(names, name)
		}
	default:
		return nil, fmt.Errorf("data.assert_type: expected must be a type name or a list of type names, got %s", expected.Type())
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("data.assert_type: expected is empty")
	}
	got := value.Type()
	for _, name := range names {
		if name == "" {
			return nil, fmt.Errorf("data.assert_type: expected contains an empty type name")
		}
		if name == got {
			return value, nil
		}
	}
	if len(names) == 1 {
		return nil, fmt.Errorf("data.assert_type: got %s, want %s", got, names[0])
	}
	return nil, fmt.Errorf("data.assert_type: got %s, want one of %s", got, strings.Join(names, ", "))
}

// data.validate(schema, value, strict=False) -> True | list[{path, message}].
// schema is a dict or a JSON/YAML string. strict=True fails instead of
// returning the error list.
func dataValidate(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var schemaVal, value starlark.Value
	var strict bool
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "schema", &schemaVal, "value", &value, "strict?", &strict); err != nil {
		return nil, err
	}
	schemaDoc, err := schemaDocument(schemaVal)
	if err != nil {
		return nil, fmt.Errorf("data.validate: schema: %w", err)
	}
	doc, err := toJSONValue(value, true)
	if err != nil {
		return nil, fmt.Errorf("data.validate: value: %w", err)
	}

	var problems []validationProblem
	err = runBounded(validateDeadline, func() error {
		var runErr error
		problems, runErr = validateAgainst(schemaDoc, doc)
		return runErr
	})
	if err != nil {
		return nil, fmt.Errorf("data.validate: %w", err)
	}
	if len(problems) == 0 {
		return starlark.True, nil
	}
	if strict {
		parts := make([]string, len(problems))
		for i, p := range problems {
			parts[i] = fmt.Sprintf("%s: %s", p.path, p.message)
		}
		return nil, fmt.Errorf("data.validate: %s", strings.Join(parts, "; "))
	}
	out := make([]starlark.Value, len(problems))
	for i, p := range problems {
		entry := starlark.NewDict(2)
		if err := entry.SetKey(starlark.String("path"), starlark.String(p.path)); err != nil {
			return nil, err
		}
		if err := entry.SetKey(starlark.String("message"), starlark.String(p.message)); err != nil {
			return nil, err
		}
		out[i] = entry
	}
	return starlark.NewList(out), nil
}

type validationProblem struct {
	path    string
	message string
}

// refuseLoader is the compiler's only URL loader: every external load fails.
type refuseLoader struct{}

func (refuseLoader) Load(string) (any, error) { return nil, errExternalRef }

func validateAgainst(schemaDoc, doc any) ([]validationProblem, error) {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(refuseLoader{})
	if err := c.AddResource(schemaResource, schemaDoc); err != nil {
		return nil, fmt.Errorf("schema: %v", err)
	}
	sch, err := c.Compile(schemaResource)
	if err != nil {
		// LoadURLError has no Unwrap; any load attempt is an external ref.
		var loadErr *jsonschema.LoadURLError
		if errors.As(err, &loadErr) || strings.Contains(err.Error(), errExternalRef.Error()) {
			return nil, errExternalRef
		}
		return nil, fmt.Errorf("schema: %v", err)
	}
	err = sch.Validate(doc)
	if err == nil {
		return nil, nil
	}
	var verr *jsonschema.ValidationError
	if !errors.As(err, &verr) {
		return nil, err
	}
	var problems []validationProblem
	seen := map[validationProblem]bool{}
	for _, unit := range verr.BasicOutput().Errors {
		if unit.Error == nil {
			continue
		}
		p := validationProblem{path: unit.InstanceLocation, message: unit.Error.String()}
		if p.path == "" {
			p.path = "/"
		}
		if !seen[p] {
			seen[p] = true
			problems = append(problems, p)
		}
	}
	if len(problems) == 0 {
		problems = append(problems, validationProblem{path: "/", message: verr.Error()})
	}
	sort.Slice(problems, func(i, j int) bool {
		if problems[i].path != problems[j].path {
			return problems[i].path < problems[j].path
		}
		return problems[i].message < problems[j].message
	})
	return problems, nil
}

// schemaDocument turns a dict or a JSON/YAML string into a JSON value.
func schemaDocument(v starlark.Value) (any, error) {
	text, ok := starlark.AsString(v)
	if !ok {
		return toJSONValue(v, true)
	}
	if len(text) > maxValidateBytes {
		return nil, fmt.Errorf("schema text exceeds %d bytes", maxValidateBytes)
	}
	if doc, err := jsonschema.UnmarshalJSON(strings.NewReader(text)); err == nil {
		return doc, nil
	}
	var raw any
	if err := yaml.Unmarshal([]byte(text), &raw); err != nil {
		return nil, fmt.Errorf("not valid JSON or YAML: %v", err)
	}
	if raw == nil {
		return nil, fmt.Errorf("schema is empty")
	}
	// Round-trip through JSON so numbers become json.Number and keys strings.
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("YAML has no JSON form: %v", err)
	}
	return jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
}

// runBounded runs fn on a worker goroutine and fails closed when the deadline
// passes first or fn panics. fn must not touch Starlark values.
func runBounded(deadline time.Duration, fn func() error) error {
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	done := make(chan error, 1)
	hook := boundedHook
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("internal error: %v", r)
			}
		}()
		if hook != nil {
			hook()
		}
		done <- fn()
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("exceeded the %s time limit (fail-closed)", deadline)
	}
}

// toJSONValue converts a Starlark value to the JSON data model with a byte
// budget of maxValidateBytes and a depth cap. With numbers set, ints and
// floats become json.Number (what the schema library expects); otherwise ints
// become int64 and floats float64.
func toJSONValue(v starlark.Value, numbers bool) (any, error) {
	c := jsonConverter{budget: maxValidateBytes, numbers: numbers}
	return c.convert(v, 0)
}

type jsonConverter struct {
	budget  int
	numbers bool
}

func (c *jsonConverter) spend(n int) error {
	c.budget -= n
	if c.budget < 0 {
		return fmt.Errorf("value exceeds %d bytes", maxValidateBytes)
	}
	return nil
}

func (c *jsonConverter) convert(v starlark.Value, depth int) (any, error) {
	if depth > maxValidateDepth {
		return nil, fmt.Errorf("value exceeds nesting depth %d", maxValidateDepth)
	}
	switch val := v.(type) {
	case starlark.NoneType:
		return nil, c.spend(4)
	case starlark.Bool:
		return bool(val), c.spend(5)
	case starlark.String:
		return string(val), c.spend(len(val) + 2)
	case starlark.Int:
		text := val.String()
		if err := c.spend(len(text)); err != nil {
			return nil, err
		}
		if c.numbers {
			return json.Number(text), nil
		}
		i, ok := val.Int64()
		if !ok {
			return nil, fmt.Errorf("integer %s does not fit in 64 bits", text)
		}
		return i, nil
	case starlark.Float:
		f := float64(val)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, fmt.Errorf("float %s is not finite", val.String())
		}
		text := strconv.FormatFloat(f, 'g', -1, 64)
		if err := c.spend(len(text)); err != nil {
			return nil, err
		}
		if c.numbers {
			return json.Number(text), nil
		}
		return f, nil
	case *GovernedStarlarkDict:
		return c.convert(val.Dict, depth)
	case *starlark.Dict:
		out := make(map[string]any, val.Len())
		for _, item := range val.Items() {
			key, ok := item[0].(starlark.String)
			if !ok {
				return nil, fmt.Errorf("dict key %s is %s, want string", item[0].String(), item[0].Type())
			}
			if err := c.spend(len(key) + 4); err != nil {
				return nil, err
			}
			elem, err := c.convert(item[1], depth+1)
			if err != nil {
				return nil, err
			}
			out[string(key)] = elem
		}
		return out, c.spend(2)
	case *starlark.List:
		return c.sequence(val, depth)
	case starlark.Tuple:
		return c.sequence(val, depth)
	default:
		return nil, fmt.Errorf("%s has no JSON form", v.Type())
	}
}

func (c *jsonConverter) sequence(seq starlark.Indexable, depth int) (any, error) {
	if err := c.spend(2); err != nil {
		return nil, err
	}
	out := make([]any, seq.Len())
	for i := range out {
		elem, err := c.convert(seq.Index(i), depth+1)
		if err != nil {
			return nil, err
		}
		if err := c.spend(1); err != nil {
			return nil, err
		}
		out[i] = elem
	}
	return out, nil
}
