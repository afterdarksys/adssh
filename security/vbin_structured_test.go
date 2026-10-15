package security

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func runStructuredBinary(t *testing.T, name string, args []string, input string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	runner, err := interp.New(
		interp.StdIO(strings.NewReader(input), &out, &errOut),
		interp.ExecHandler(func(ctx context.Context, _ []string) error {
			return structuredBinary{name: name}.Run(ctx, args)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader("invoke"), "")
	if err != nil {
		t.Fatal(err)
	}
	runErr := runner.Run(context.Background(), file)
	if runErr == nil && errOut.Len() > 0 {
		runErr = fmt.Errorf("%s", strings.TrimSpace(errOut.String()))
	}
	return out.String(), runErr
}

func TestStructuredPipelineJSONWhereSelectAndToJSON(t *testing.T) {
	input := `[{"name":"api","cpu":75},{"name":"worker","cpu":20}]`
	jsonl, err := runStructuredBinary(t, "from", []string{"from", "json"}, input)
	if err != nil {
		t.Fatal(err)
	}
	filtered, err := runStructuredBinary(t, "where", []string{"where", `row["cpu"] > 50`}, jsonl)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := runStructuredBinary(t, "select", []string{"select", "name,cpu"}, filtered)
	if err != nil {
		t.Fatal(err)
	}
	output, err := runStructuredBinary(t, "to", []string{"to", "json"}, selected)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(output); got != `[{"cpu":75,"name":"api"}]` {
		t.Fatalf("pipeline output = %s", got)
	}
}

func TestFromCSVEmitsJSONLObjects(t *testing.T) {
	output, err := runStructuredBinary(t, "from", []string{"from", "csv"}, "name,cpu\napi,75\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(output); got != `{"cpu":"75","name":"api"}` {
		t.Fatalf("CSV output = %s", got)
	}
}

func TestYAMLPipelineFeedsStructCheck(t *testing.T) {
	input := "- name: api\n  cpu: 75\n- name: worker\n  cpu: 20\n"
	jsonl, err := runStructuredBinary(t, "from", []string{"from", "yaml"}, input)
	if err != nil {
		t.Fatal(err)
	}
	filtered, err := runStructuredBinary(t, "where", []string{"where", `row["cpu"] > 50`}, jsonl)
	if err != nil {
		t.Fatal(err)
	}
	output, err := runStructuredBinary(t, "to", []string{"to", "struct", "name:string,cpu:int"}, filtered)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(output); got != `[{"cpu":75,"name":"api"}]` {
		t.Fatalf("yaml pipeline = %s", got)
	}
}

func TestYAMLAliasIsRejectedBeforeExpansion(t *testing.T) {
	input := "a: &a\n  name: secret-value\nb: *a\n"
	output, err := runStructuredBinary(t, "from", []string{"from", "yaml"}, input)
	if err == nil || !strings.Contains(err.Error(), "aliases") {
		t.Fatalf("expected alias rejection, got %v", err)
	}
	if strings.Contains(output, "secret-value") {
		t.Fatalf("alias expanded into output: %s", output)
	}
}

func TestYAMLNestedAliasIsRejected(t *testing.T) {
	input := "- &item\n  name: secret-value\n- *item\n"
	output, err := runStructuredBinary(t, "from", []string{"from", "yaml"}, input)
	if err == nil || !strings.Contains(err.Error(), "aliases") {
		t.Fatalf("expected alias rejection, got %v", err)
	}
	if output != "" {
		t.Fatalf("output %s", output)
	}
}

func TestYAMLOversizeIsRejected(t *testing.T) {
	input := strings.Repeat("a", structuredMaxYAML+1)
	output, err := runStructuredBinary(t, "from", []string{"from", "yaml"}, input)
	if err == nil || !strings.Contains(err.Error(), "1 MiB") {
		t.Fatalf("expected 1 MiB rejection, got %v", err)
	}
	if output != "" {
		t.Fatal("oversized yaml produced output")
	}
}

func TestYAMLTimestampFailsClosed(t *testing.T) {
	_, err := runStructuredBinary(t, "from", []string{"from", "yaml"}, "seen: 2020-01-02T03:04:05Z\n")
	if err == nil || !strings.Contains(err.Error(), "unsupported value") {
		t.Fatalf("expected unsupported timestamp, got %v", err)
	}
}

func TestStructRejectsUnknownFieldTypeMismatchAndTrailingData(t *testing.T) {
	spec := []string{"from", "struct", "name:string,cpu:int"}
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"unknown", `{"name":"api","cpu":1,"extra":true}`, "unknown field"},
		{"type", `{"name":"api","cpu":"75"}`, "type mismatch"},
		{"missing", `{"name":"api"}`, "missing field"},
		{"trailing", `{"name":"api","cpu":1} trailing`, "trailing data"},
		{"second value", `{"name":"api","cpu":1}{"name":"db","cpu":2}`, "trailing data"},
		{"scalar", `"api"`, "type mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := runStructuredBinary(t, "from", spec, tc.input)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
			if output != "" {
				t.Fatalf("failed struct decode produced %s", output)
			}
		})
	}
}

func TestToStructRejectsNonObject(t *testing.T) {
	output, err := runStructuredBinary(t, "to", []string{"to", "struct"}, "1\n")
	if err == nil || !strings.Contains(err.Error(), "type mismatch") {
		t.Fatalf("expected type mismatch, got %v", err)
	}
	if output != "" {
		t.Fatalf("output %s", output)
	}
}

func TestGobFormatIsUnsupported(t *testing.T) {
	for _, name := range []string{"from", "to"} {
		_, err := runStructuredBinary(t, name, []string{name, "gob"}, "{}\n")
		if err == nil || !strings.Contains(err.Error(), "unsupported format") {
			t.Fatalf("%s gob: %v", name, err)
		}
	}
}

func TestWhereRejectsNonBooleanPredicate(t *testing.T) {
	_, err := runStructuredBinary(t, "where", []string{"where", `row["cpu"]`}, `{"cpu":75}`+"\n")
	if err == nil || !strings.Contains(err.Error(), "boolean") {
		t.Fatalf("expected boolean predicate error, got %v", err)
	}
}
