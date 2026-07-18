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

func TestWhereRejectsNonBooleanPredicate(t *testing.T) {
	_, err := runStructuredBinary(t, "where", []string{"where", `row["cpu"]`}, `{"cpu":75}`+"\n")
	if err == nil || !strings.Contains(err.Error(), "boolean") {
		t.Fatalf("expected boolean predicate error, got %v", err)
	}
}
