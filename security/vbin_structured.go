package security

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"

	"go.starlark.net/starlark"
	"gopkg.in/yaml.v3"
	"mvdan.cc/sh/v3/interp"
)

// Threats: a YAML alias expands before the record cap is applied, so an alias
// node is rejected before expansion. YAML input larger than 1 MiB is refused.
// The struct format is JSON. Unknown fields, a mismatched type, a missing
// field, and trailing bytes fail closed. encoding/gob is not accepted.

const (
	structuredMaxInput   = 64 << 20
	structuredMaxYAML    = 1 << 20
	structuredMaxRecord  = 1 << 20
	structuredMaxRecords = 100000
)

type structuredBinary struct{ name string }

func (b structuredBinary) Name() string { return b.name }
func (b structuredBinary) Description() string {
	switch b.name {
	case "from":
		return "Decode JSON, JSONL, CSV, YAML, or struct-shaped JSON into a JSONL stream"
	case "where":
		return "Filter JSONL records with a Starlark predicate"
	case "select":
		return "Project fields from JSONL records"
	case "to":
		return "Encode JSONL records as JSON, JSONL, CSV, YAML, struct-shaped JSON, or a table"
	default:
		return "Structured data pipeline command"
	}
}
func (b structuredBinary) Usage() string {
	switch b.name {
	case "from":
		return "from <json|jsonl|ndjson|csv|yaml|struct> [field:type,...]"
	case "where":
		return "where <starlark-expression-using-row>"
	case "select":
		return "select <field[,field...]>"
	case "to":
		return "to <json|jsonl|ndjson|csv|table|yaml|struct> [field:type,...]"
	default:
		return b.name
	}
}

func (b structuredBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	switch b.name {
	case "from":
		spec, err := structuredSpec(args, "from")
		if err != nil {
			return err
		}
		return structuredFrom(hc.Stdin, hc.Stdout, args[1], spec)
	case "where":
		if len(args) < 2 {
			return fmt.Errorf("where: usage: %s", b.Usage())
		}
		return structuredWhere(hc.Stdin, hc.Stdout, strings.Join(args[1:], " "))
	case "select":
		if len(args) != 2 {
			return fmt.Errorf("select: usage: %s", b.Usage())
		}
		return structuredSelect(hc.Stdin, hc.Stdout, strings.Split(args[1], ","))
	case "to":
		spec, err := structuredSpec(args, "to")
		if err != nil {
			return err
		}
		return structuredTo(hc.Stdin, hc.Stdout, args[1], spec)
	default:
		return fmt.Errorf("structured: unsupported command %q", b.name)
	}
}

func structuredSpec(args []string, command string) (string, error) {
	usage := structuredBinary{name: command}.Usage()
	if len(args) < 2 || len(args) > 3 {
		return "", fmt.Errorf("%s: usage: %s", command, usage)
	}
	if len(args) == 3 && strings.ToLower(args[1]) != "struct" {
		return "", fmt.Errorf("%s: usage: %s", command, usage)
	}
	if len(args) == 3 {
		return args[2], nil
	}
	return "", nil
}

func structuredFrom(input io.Reader, output io.Writer, format string, spec string) error {
	switch strings.ToLower(format) {
	case "json":
		decoder := json.NewDecoder(io.LimitReader(input, structuredMaxInput))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("from json: %w", err)
		}
		values, ok := value.([]any)
		if !ok {
			values = []any{value}
		}
		if len(values) > structuredMaxRecords {
			return fmt.Errorf("from json: record limit %d exceeded", structuredMaxRecords)
		}
		for _, record := range values {
			if err := writeJSONLine(output, record); err != nil {
				return err
			}
		}
		return nil
	case "jsonl", "ndjson":
		return scanJSONL(input, func(record any) error { return writeJSONLine(output, record) })
	case "csv":
		reader := csv.NewReader(io.LimitReader(input, structuredMaxInput))
		headers, err := reader.Read()
		if err != nil {
			return fmt.Errorf("from csv: read header: %w", err)
		}
		if len(headers) == 0 {
			return fmt.Errorf("from csv: empty header")
		}
		seen := map[string]bool{}
		for _, header := range headers {
			if header == "" || seen[header] {
				return fmt.Errorf("from csv: headers must be non-empty and unique")
			}
			seen[header] = true
		}
		for count := 0; ; count++ {
			if count >= structuredMaxRecords {
				return fmt.Errorf("from csv: record limit %d exceeded", structuredMaxRecords)
			}
			row, err := reader.Read()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return fmt.Errorf("from csv: %w", err)
			}
			record := make(map[string]any, len(headers))
			for i, header := range headers {
				record[header] = row[i]
			}
			if err := writeJSONLine(output, record); err != nil {
				return err
			}
		}
	case "yaml":
		return structuredFromYAML(input, output)
	case "struct":
		return structuredFromStruct(input, output, spec)
	default:
		return fmt.Errorf("from: unsupported format %q", format)
	}
}

func structuredWhere(input io.Reader, output io.Writer, expression string) error {
	thread := &starlark.Thread{Name: "where"}
	return scanJSONL(input, func(record any) error {
		row, err := valueToStarlark(record)
		if err != nil {
			return fmt.Errorf("where: %w", err)
		}
		result, err := starlark.Eval(thread, "<where>", expression, starlark.StringDict{"row": row})
		if err != nil {
			return fmt.Errorf("where: evaluate predicate: %w", err)
		}
		keep, ok := result.(starlark.Bool)
		if !ok {
			return fmt.Errorf("where: predicate must return boolean, got %s", result.Type())
		}
		if bool(keep) {
			return writeJSONLine(output, record)
		}
		return nil
	})
}

func structuredSelect(input io.Reader, output io.Writer, fields []string) error {
	clean := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			return fmt.Errorf("select: fields must not be empty")
		}
		clean = append(clean, field)
	}
	return scanJSONL(input, func(record any) error {
		object, ok := record.(map[string]any)
		if !ok {
			return fmt.Errorf("select: record must be an object")
		}
		selected := make(map[string]any, len(clean))
		for _, field := range clean {
			value, found := dottedValue(object, field)
			if !found {
				value = nil
			}
			selected[field] = value
		}
		return writeJSONLine(output, selected)
	})
}

func structuredTo(input io.Reader, output io.Writer, format string, spec string) error {
	var records []any
	if err := scanJSONL(input, func(record any) error {
		records = append(records, record)
		return nil
	}); err != nil {
		return err
	}
	switch strings.ToLower(format) {
	case "json":
		encoder := json.NewEncoder(output)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(records)
	case "jsonl", "ndjson":
		for _, record := range records {
			if err := writeJSONLine(output, record); err != nil {
				return err
			}
		}
		return nil
	case "csv":
		objects, fields, err := structuredObjects(records)
		if err != nil {
			return fmt.Errorf("to csv: %w", err)
		}
		writer := csv.NewWriter(output)
		if err := writer.Write(fields); err != nil {
			return err
		}
		for _, object := range objects {
			row := make([]string, len(fields))
			for i, field := range fields {
				row[i] = scalarString(object[field])
			}
			if err := writer.Write(row); err != nil {
				return err
			}
		}
		writer.Flush()
		return writer.Error()
	case "table":
		objects, fields, err := structuredObjects(records)
		if err != nil {
			return fmt.Errorf("to table: %w", err)
		}
		return writeTable(output, objects, fields)
	case "yaml":
		return structuredToYAML(output, records)
	case "struct":
		return structuredToStruct(output, records, spec)
	default:
		return fmt.Errorf("to: unsupported format %q", format)
	}
}

func structuredFromYAML(input io.Reader, output io.Writer) error {
	raw, err := readAtMost(input, structuredMaxYAML)
	if err != nil {
		return fmt.Errorf("from yaml: %w", err)
	}
	if len(raw) > structuredMaxYAML {
		return fmt.Errorf("from yaml: input exceeds 1 MiB")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var records []any
	for {
		var node yaml.Node
		err := decoder.Decode(&node)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("from yaml: %w", err)
		}
		if err := rejectYAMLAliases(&node); err != nil {
			return fmt.Errorf("from yaml: %w", err)
		}
		var value any
		if err := node.Decode(&value); err != nil {
			return fmt.Errorf("from yaml: %w", err)
		}
		records, err = appendStructuredValue(records, value, true)
		if err != nil {
			return fmt.Errorf("from yaml: %w", err)
		}
		if len(records) > structuredMaxRecords {
			return fmt.Errorf("from yaml: record limit %d exceeded", structuredMaxRecords)
		}
	}
	for _, record := range records {
		if err := writeJSONLine(output, record); err != nil {
			return err
		}
	}
	return nil
}

// errYAMLAlias is returned by rejectYAMLAliases. Callers add their prefix.
var errYAMLAlias = errors.New("aliases are not allowed")

// rejectYAMLAliases fails on any alias node, so an alias bomb cannot expand.
// Plugin manifests and `from yaml` share it.
func rejectYAMLAliases(node *yaml.Node) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.AliasNode || node.Alias != nil {
		return errYAMLAlias
	}
	for _, child := range node.Content {
		if err := rejectYAMLAliases(child); err != nil {
			return err
		}
	}
	return nil
}

func structuredToYAML(output io.Writer, records []any) error {
	values := make([]any, len(records))
	for i, record := range records {
		converted, err := valueForYAML(record)
		if err != nil {
			return err
		}
		values[i] = converted
	}
	encoder := yaml.NewEncoder(output)
	encoder.SetIndent(2)
	if err := encoder.Encode(values); err != nil {
		_ = encoder.Close()
		return fmt.Errorf("to yaml: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return fmt.Errorf("to yaml: %w", err)
	}
	return nil
}

type structField struct {
	name string
	kind string
}

func structuredFromStruct(input io.Reader, output io.Writer, spec string) error {
	fields, err := parseStructSpec(spec)
	if err != nil {
		return fmt.Errorf("from struct: %w", err)
	}
	raw, err := readAtMost(input, structuredMaxInput)
	if err != nil {
		return fmt.Errorf("from struct: %w", err)
	}
	if len(raw) > structuredMaxInput {
		return fmt.Errorf("from struct: input exceeds 64 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("from struct: %w", err)
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return fmt.Errorf("from struct: %w", err)
	}
	records, err := appendStructuredValue(nil, value, false)
	if err != nil {
		return fmt.Errorf("from struct: %w", err)
	}
	if len(records) > structuredMaxRecords {
		return fmt.Errorf("from struct: record limit %d exceeded", structuredMaxRecords)
	}
	for i, record := range records {
		if err := checkStructRecord(record, fields); err != nil {
			return fmt.Errorf("from struct: record %d: %w", i+1, err)
		}
	}
	for _, record := range records {
		if err := writeJSONLine(output, record); err != nil {
			return err
		}
	}
	return nil
}

func structuredToStruct(output io.Writer, records []any, spec string) error {
	fields, err := parseStructSpec(spec)
	if err != nil {
		return fmt.Errorf("to struct: %w", err)
	}
	for i, record := range records {
		if err := checkStructRecord(record, fields); err != nil {
			return fmt.Errorf("to struct: record %d: %w", i+1, err)
		}
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(records); err != nil {
		return fmt.Errorf("to struct: %w", err)
	}
	return nil
}

func parseStructSpec(spec string) ([]structField, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, nil
	}
	parts := strings.Split(spec, ",")
	fields := make([]structField, 0, len(parts))
	seen := map[string]bool{}
	for _, part := range parts {
		name, kind, ok := strings.Cut(strings.TrimSpace(part), ":")
		if !ok || name == "" || kind == "" {
			return nil, fmt.Errorf("field spec must be name:type")
		}
		if !validStarlarkIdent(name) {
			return nil, fmt.Errorf("invalid field name %q", name)
		}
		kind = strings.ToLower(kind)
		switch kind {
		case "string", "int", "float", "bool", "object", "array", "any":
		default:
			return nil, fmt.Errorf("unknown type %q", kind)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate field %q", name)
		}
		seen[name] = true
		fields = append(fields, structField{name: name, kind: kind})
	}
	return fields, nil
}

func checkStructRecord(record any, fields []structField) error {
	object, ok := record.(map[string]any)
	if !ok {
		return fmt.Errorf("type mismatch: want object, got %T", record)
	}
	if len(fields) == 0 {
		return nil
	}
	seen := map[string]bool{}
	for _, field := range fields {
		value, found := object[field.name]
		if !found {
			return fmt.Errorf("missing field %q", field.name)
		}
		if err := checkStructValue(value, field.kind); err != nil {
			return fmt.Errorf("field %q: %w", field.name, err)
		}
		seen[field.name] = true
	}
	for key := range object {
		if !seen[key] {
			return fmt.Errorf("unknown field %q", key)
		}
	}
	return nil
}

func checkStructValue(value any, kind string) error {
	switch kind {
	case "any":
		return nil
	case "string":
		if _, ok := value.(string); ok {
			return nil
		}
	case "bool":
		if _, ok := value.(bool); ok {
			return nil
		}
	case "int":
		if structIntOK(value) {
			return nil
		}
	case "float":
		if structFloatOK(value) {
			return nil
		}
	case "object":
		if _, ok := value.(map[string]any); ok {
			return nil
		}
	case "array":
		if _, ok := value.([]any); ok {
			return nil
		}
	default:
		return fmt.Errorf("unknown type %q", kind)
	}
	return fmt.Errorf("type mismatch: want %s, got %T", kind, value)
}

func structIntOK(value any) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	text := string(number)
	if text == "" || strings.ContainsAny(text, ".eE") {
		return false
	}
	_, err := strconv.ParseInt(text, 10, 64)
	return err == nil
}

func structFloatOK(value any) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	parsed, err := strconv.ParseFloat(string(number), 64)
	return err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0)
}

func rejectTrailingJSON(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return fmt.Errorf("trailing data: %w", err)
	}
	return fmt.Errorf("trailing data")
}

func appendStructuredValue(records []any, value any, fromYAML bool) ([]any, error) {
	if fromYAML {
		// normalizeYAMLValue is recursive, so list items are already done.
		var err error
		value, err = normalizeYAMLValue(value)
		if err != nil {
			return nil, err
		}
	}
	if items, ok := value.([]any); ok {
		return append(records, items...), nil
	}
	return append(records, value), nil
}

func normalizeYAMLValue(value any) (any, error) {
	switch value := value.(type) {
	case nil, bool, string:
		return value, nil
	case int:
		return json.Number(strconv.Itoa(value)), nil
	case int64:
		return json.Number(strconv.FormatInt(value, 10)), nil
	case uint64:
		if value > uint64(math.MaxInt64) {
			return nil, fmt.Errorf("integer out of range")
		}
		return json.Number(strconv.FormatUint(value, 10)), nil
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return nil, fmt.Errorf("non-finite number")
		}
		return json.Number(strconv.FormatFloat(value, 'f', -1, 64)), nil
	case json.Number:
		return value, nil
	case []any:
		items := make([]any, len(value))
		for i, item := range value {
			converted, err := normalizeYAMLValue(item)
			if err != nil {
				return nil, err
			}
			items[i] = converted
		}
		return items, nil
	case map[string]any:
		object := make(map[string]any, len(value))
		for key, item := range value {
			converted, err := normalizeYAMLValue(item)
			if err != nil {
				return nil, err
			}
			object[key] = converted
		}
		return object, nil
	case map[any]any:
		object := make(map[string]any, len(value))
		for key, item := range value {
			name, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("mapping keys must be strings")
			}
			converted, err := normalizeYAMLValue(item)
			if err != nil {
				return nil, err
			}
			object[name] = converted
		}
		return object, nil
	default:
		return nil, fmt.Errorf("unsupported value %T", value)
	}
}

func valueForYAML(value any) (any, error) {
	switch value := value.(type) {
	case nil, bool, string:
		return value, nil
	case json.Number:
		text := string(value)
		if !strings.ContainsAny(text, ".eE") {
			parsed, err := strconv.ParseInt(text, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("to yaml: integer: %w", err)
			}
			return parsed, nil
		}
		parsed, err := strconv.ParseFloat(text, 64)
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			return nil, fmt.Errorf("to yaml: non-finite number")
		}
		return parsed, nil
	case []any:
		items := make([]any, len(value))
		for i, item := range value {
			converted, err := valueForYAML(item)
			if err != nil {
				return nil, err
			}
			items[i] = converted
		}
		return items, nil
	case map[string]any:
		object := make(map[string]any, len(value))
		for key, item := range value {
			converted, err := valueForYAML(item)
			if err != nil {
				return nil, err
			}
			object[key] = converted
		}
		return object, nil
	default:
		return nil, fmt.Errorf("to yaml: unsupported value %T", value)
	}
}

func readAtMost(input io.Reader, limit int) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(input, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func scanJSONL(input io.Reader, visit func(any) error) error {
	scanner := bufio.NewScanner(io.LimitReader(input, structuredMaxInput))
	scanner.Buffer(make([]byte, 64*1024), structuredMaxRecord)
	count := 0
	for scanner.Scan() {
		line := bytesTrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		count++
		if count > structuredMaxRecords {
			return fmt.Errorf("structured: record limit %d exceeded", structuredMaxRecords)
		}
		decoder := json.NewDecoder(strings.NewReader(string(line)))
		decoder.UseNumber()
		var record any
		if err := decoder.Decode(&record); err != nil {
			return fmt.Errorf("structured: invalid JSONL record %d: %w", count, err)
		}
		if err := visit(record); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("structured: scan JSONL: %w", err)
	}
	return nil
}

func bytesTrimSpace(value []byte) []byte { return []byte(strings.TrimSpace(string(value))) }

func writeJSONLine(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("structured: encode JSONL: %w", err)
	}
	return nil
}

func valueToStarlark(value any) (starlark.Value, error) {
	switch value := value.(type) {
	case nil:
		return starlark.None, nil
	case bool:
		return starlark.Bool(value), nil
	case string:
		return starlark.String(value), nil
	case json.Number:
		if integer, err := strconv.ParseInt(string(value), 10, 64); err == nil {
			return starlark.MakeInt64(integer), nil
		}
		float, err := strconv.ParseFloat(string(value), 64)
		if err != nil {
			return nil, err
		}
		return starlark.Float(float), nil
	case float64:
		return starlark.Float(value), nil
	case []any:
		items := make([]starlark.Value, len(value))
		for i, item := range value {
			converted, err := valueToStarlark(item)
			if err != nil {
				return nil, err
			}
			items[i] = converted
		}
		return starlark.NewList(items), nil
	case map[string]any:
		dict := starlark.NewDict(len(value))
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			converted, err := valueToStarlark(value[key])
			if err != nil {
				return nil, err
			}
			if err := dict.SetKey(starlark.String(key), converted); err != nil {
				return nil, err
			}
		}
		return dict, nil
	default:
		return nil, fmt.Errorf("unsupported structured value %T", value)
	}
}

func dottedValue(object map[string]any, path string) (any, bool) {
	var current any = object
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func structuredObjects(records []any) ([]map[string]any, []string, error) {
	objects := make([]map[string]any, len(records))
	fieldSet := map[string]bool{}
	for i, record := range records {
		object, ok := record.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("record %d must be an object", i+1)
		}
		objects[i] = object
		for field := range object {
			fieldSet[field] = true
		}
	}
	fields := make([]string, 0, len(fieldSet))
	for field := range fieldSet {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	return objects, fields, nil
}

func scalarString(value any) string {
	switch value := value.(type) {
	case nil:
		return ""
	case string:
		return value
	case json.Number:
		return string(value)
	case bool:
		return strconv.FormatBool(value)
	default:
		encoded, _ := json.Marshal(value)
		return string(encoded)
	}
}

func writeTable(output io.Writer, objects []map[string]any, fields []string) error {
	widths := make([]int, len(fields))
	for i, field := range fields {
		widths[i] = len(field)
	}
	for _, object := range objects {
		for i, field := range fields {
			widths[i] = min(60, max(widths[i], len(scalarString(object[field]))))
		}
	}
	writeRow := func(values []string) error {
		for i, value := range values {
			if len(value) > widths[i] {
				value = value[:max(0, widths[i]-1)] + "…"
			}
			if _, err := fmt.Fprintf(output, "%-*s", widths[i], value); err != nil {
				return err
			}
			if i+1 < len(values) {
				_, _ = io.WriteString(output, "  ")
			}
		}
		_, err := io.WriteString(output, "\n")
		return err
	}
	if err := writeRow(fields); err != nil {
		return err
	}
	for _, object := range objects {
		row := make([]string, len(fields))
		for i, field := range fields {
			row[i] = scalarString(object[field])
		}
		if err := writeRow(row); err != nil {
			return err
		}
	}
	return nil
}
