package security

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/itchyny/gojq"
	"gopkg.in/yaml.v3"
	"mvdan.cc/sh/v3/interp"
)

// jq — JSON processor

type jqBinary struct{}

func (jqBinary) Name() string        { return "jq" }
func (jqBinary) Description() string { return "JSON processor — filter and transform JSON input" }
func (jqBinary) Usage() string       { return "jq <filter>" }

func (jqBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	if len(args) < 2 {
		return fmt.Errorf("jq: missing filter argument")
	}

	filter, err := gojq.Parse(args[1])
	if err != nil {
		return fmt.Errorf("jq: invalid filter: %v", err)
	}

	inputBytes, err := io.ReadAll(hc.Stdin)
	if err != nil {
		return fmt.Errorf("jq: read error: %v", err)
	}

	var input interface{}
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		return fmt.Errorf("jq: invalid json input: %v", err)
	}

	iter := filter.Run(input)
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if err, ok := v.(error); ok {
			return fmt.Errorf("jq: execution error: %v", err)
		}
		outBytes, _ := json.MarshalIndent(v, "", "  ")
		fmt.Fprintf(hc.Stdout, "%s\n", outBytes)
	}
	return nil
}

// yq — YAML processor

type yqBinary struct{}

func (yqBinary) Name() string        { return "yq" }
func (yqBinary) Description() string { return "YAML processor — filter and transform YAML input" }
func (yqBinary) Usage() string       { return "yq <filter>" }

func (yqBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	if len(args) < 2 {
		return fmt.Errorf("yq: missing filter argument")
	}

	filter, err := gojq.Parse(args[1])
	if err != nil {
		return fmt.Errorf("yq: invalid filter: %v", err)
	}

	inputBytes, err := io.ReadAll(hc.Stdin)
	if err != nil {
		return fmt.Errorf("yq: read error: %v", err)
	}

	var raw interface{}
	if err := yaml.Unmarshal(inputBytes, &raw); err != nil {
		return fmt.Errorf("yq: invalid yaml input: %v", err)
	}

	// yaml.v3 can produce map[string]interface{} or map[interface{}]interface{};
	// round-trip through JSON to normalize for gojq.
	jsonBytes, _ := json.Marshal(raw)
	var input interface{}
	if err := json.Unmarshal(jsonBytes, &input); err != nil {
		return fmt.Errorf("yq: invalid data: %v", err)
	}

	iter := filter.Run(input)
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if err, ok := v.(error); ok {
			return fmt.Errorf("yq: execution error: %v", err)
		}
		outBytes, _ := yaml.Marshal(v)
		fmt.Fprintf(hc.Stdout, "%s---\n", outBytes)
	}
	return nil
}

// http — simple HTTP client

type httpBinary struct{}

func (httpBinary) Name() string { return "http" }
func (httpBinary) Description() string {
	return "Simple HTTP client — GET a URL and print the response"
}
func (httpBinary) Usage() string { return "http <url>" }

func (httpBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	if len(args) < 2 {
		return fmt.Errorf("http: missing url argument")
	}

	resp, err := http.Get(args[1])
	if err != nil {
		return fmt.Errorf("http: %v", err)
	}
	defer resp.Body.Close()

	_, err = io.Copy(hc.Stdout, resp.Body)
	return err
}

// darkscan — malware scanner (simulated)

type darkscanBinary struct{}

func (darkscanBinary) Name() string { return "darkscan" }
func (darkscanBinary) Description() string {
	return "Demo malware scanner — simulated output only"
}
func (darkscanBinary) Usage() string { return "darkscan <file>" }

func (darkscanBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	if len(args) < 2 {
		return fmt.Errorf("darkscan: missing file argument")
	}

	fmt.Fprintln(hc.Stdout, "SIMULATED — NO SECURITY VERDICT")
	fmt.Fprintf(hc.Stdout, "Demo input: %s\n", args[1])
	fmt.Fprintln(hc.Stdout, "No file was uploaded or scanned.")
	return nil
}

// memforensics — memory forensics (simulated)

type memforensicsBinary struct{}

func (memforensicsBinary) Name() string { return "memforensics" }
func (memforensicsBinary) Description() string {
	return "Demo memory forensics — simulated output only"
}
func (memforensicsBinary) Usage() string { return "memforensics <pid>" }

func (memforensicsBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	if len(args) < 2 {
		return fmt.Errorf("memforensics: missing pid argument")
	}

	fmt.Fprintln(hc.Stdout, "SIMULATED — NO SECURITY VERDICT")
	fmt.Fprintf(hc.Stdout, "Demo process ID: %s\n", args[1])
	fmt.Fprintln(hc.Stdout, "No process was attached to or inspected.")
	return nil
}

func init() {
	Register(jqBinary{})
	Register(yqBinary{})
	Register(httpBinary{})
	Register(darkscanBinary{})
	Register(memforensicsBinary{})
}
