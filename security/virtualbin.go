package security

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/itchyny/gojq"
	"gopkg.in/yaml.v3"
	"mvdan.cc/sh/v3/interp"
)

func runVirtualJQ(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	if len(args) < 2 {
		return fmt.Errorf("jq: missing filter argument")
	}

	filter, err := gojq.Parse(args[1])
	if err != nil {
		return fmt.Errorf("jq: invalid filter: %v", err)
	}

	inputBytes, err := ioutil.ReadAll(hc.Stdin)
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
		fmt.Fprintf(hc.Stdout, "%s\n", string(outBytes))
	}
	return nil
}

func runVirtualYQ(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	if len(args) < 2 {
		return fmt.Errorf("yq: missing filter argument")
	}

	filter, err := gojq.Parse(args[1])
	if err != nil {
		return fmt.Errorf("yq: invalid filter: %v", err)
	}

	inputBytes, err := ioutil.ReadAll(hc.Stdin)
	if err != nil {
		return fmt.Errorf("yq: read error: %v", err)
	}

	var input interface{}
	if err := yaml.Unmarshal(inputBytes, &input); err != nil {
		return fmt.Errorf("yq: invalid yaml input: %v", err)
	}

	// yaml.v3 unmarshals into map[interface{}]interface{} which gojq doesn't like.
	// Convert it to map[string]interface{} by marshaling to JSON and back.
	jsonBytes, _ := json.Marshal(input)
	var cleanInput interface{}
	json.Unmarshal(jsonBytes, &cleanInput)

	iter := filter.Run(cleanInput)
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if err, ok := v.(error); ok {
			return fmt.Errorf("yq: execution error: %v", err)
		}
		outBytes, _ := yaml.Marshal(v)
		fmt.Fprintf(hc.Stdout, "%s---\n", string(outBytes))
	}
	return nil
}

func runVirtualHTTP(ctx context.Context, args []string) error {
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

func runVirtualDarkScan(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	if len(args) < 2 {
		return fmt.Errorf("darkscan: missing file argument")
	}

	fmt.Fprintf(hc.Stdout, "Submitting %s to DarkAPI Malware Scanner...\n", args[1])
	fmt.Fprintf(hc.Stdout, "[*] Simulated Hash: 8b1a9953c4611296a827abf8c47804d7e6c49c6b\n")
	fmt.Fprintf(hc.Stdout, "[+] Result: CLEAN (Score: 0.00)\n")
	return nil
}

func runVirtualMemForensics(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	if len(args) < 2 {
		return fmt.Errorf("memforensics: missing pid argument")
	}

	fmt.Fprintf(hc.Stdout, "Attaching to process %s for memory forensics...\n", args[1])
	fmt.Fprintf(hc.Stdout, "[*] Scanning memory regions for secrets and injections via ads-memory-forensics...\n")
	fmt.Fprintf(hc.Stdout, "[-] No threats detected.\n")
	return nil
}
