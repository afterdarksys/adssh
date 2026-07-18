package security

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
)

const (
	structuredMaxInput   = 64 << 20
	structuredMaxRecord  = 1 << 20
	structuredMaxRecords = 100000
)

type structuredBinary struct{ name string }

func (b structuredBinary) Name() string { return b.name }
func (b structuredBinary) Description() string {
	switch b.name {
	case "from":
		return "Decode JSON, JSONL, or CSV into a JSONL structured stream"
	case "where":
		return "Filter JSONL records with a Starlark predicate"
	case "select":
		return "Project fields from JSONL records"
	case "to":
		return "Encode JSONL records as JSON, JSONL, CSV, or a table"
	default:
		return "Structured data pipeline command"
	}
}
func (b structuredBinary) Usage() string {
	switch b.name {
	case "from":
		return "from <json|jsonl|csv>"
	case "where":
		return "where <starlark-expression-using-row>"
	case "select":
		return "select <field[,field...]>"
	case "to":
		return "to <json|jsonl|csv|table>"
	default:
		return b.name
	}
}

func (b structuredBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	switch b.name {
	case "from":
		if len(args) != 2 {
			return fmt.Errorf("from: usage: %s", b.Usage())
		}
		return structuredFrom(hc.Stdin, hc.Stdout, args[1])
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
		if len(args) != 2 {
			return fmt.Errorf("to: usage: %s", b.Usage())
		}
		return structuredTo(hc.Stdin, hc.Stdout, args[1])
	default:
		return fmt.Errorf("structured: unsupported command %q", b.name)
	}
}

func structuredFrom(input io.Reader, output io.Writer, format string) error {
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

func structuredTo(input io.Reader, output io.Writer, format string) error {
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
	default:
		return fmt.Errorf("to: unsupported format %q", format)
	}
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
