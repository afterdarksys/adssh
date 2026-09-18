package security

import (
	"reflect"
	"testing"
)

func TestClassifyCapabilities(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		// Non-starlark (shell-layer) commands are never classified.
		{"external binary", "ls", nil},
		{"external with path", "/bin/git", nil},
		{"mvdan builtin", "cd", nil},

		// Namespaced builtins.
		{"net", "starlark.net.tcp_send", []string{CapNet, CapTCP}},
		{"regex", "starlark.re.match", []string{CapRegex}},
		{"db", "starlark.db.query", []string{CapDatabases}},
		{"fs", "starlark.fs.write", []string{CapFileops}},
		{"crypto", "starlark.crypto.sha256", []string{CapCrypto}},
		{"data", "starlark.data.json_parse", []string{CapData}},
		{"strings", "starlark.str.split", []string{CapStrings}},
		{"secrets folds security", "starlark.secrets.get", []string{CapSecrets, CapSecurity}},

		// Cloud providers all fold to cloud.
		{"aws", "starlark.aws.ec2.run_instances", []string{CapCloud}},
		{"gcp", "starlark.gcp.compute", []string{CapCloud}},
		{"azure", "starlark.azure.vm", []string{CapCloud}},
		{"oci", "starlark.oci.instance", []string{CapCloud}},
		{"cloud", "starlark.cloud.gen", []string{CapCloud}},

		// sys is refined per function.
		{"sys read_file", "starlark.sys.read_file", []string{CapFileops}},
		{"sys write_file", "starlark.sys.write_file", []string{CapFileops}},
		{"sys exec_cmd", "starlark.sys.exec_cmd", []string{CapProc, CapStdio}},
		{"sys exec_json", "starlark.sys.exec_json", []string{CapProc, CapStdio}},
		{"sys getenv", "starlark.sys.getenv", []string{CapStdio}},
		{"sys unknown fn", "starlark.sys.something_new", []string{CapStdio}},
		{"sys no fn", "starlark.sys", []string{CapStdio}},

		// Fail-closed hook for an unknown namespace.
		{"unknown ns", "starlark.wat.thing", []string{CapUnclassified}},
		{"bare prefix", "starlark.", []string{CapUnclassified}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyCapabilities(tc.command)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ClassifyCapabilities(%q) = %v, want %v", tc.command, got, tc.want)
			}
		})
	}
}

func TestClassifyCapabilitiesSortedUnique(t *testing.T) {
	got := ClassifyCapabilities("starlark.net.dial")
	if len(got) != 2 || got[0] != CapNet || got[1] != CapTCP {
		t.Fatalf("expected sorted [net tcp], got %v", got)
	}
}

// A capability-scoped policy: deny the "cloud" group, allow "strings". Proves
// input.capabilities flows from ClassifyCapabilities through the gate into Rego.
const capPolicy = `
package adssh.authz
import future.keywords.in
import future.keywords.every
default allow = false
default deny_reason = "denied"
allow {
    every c in input.capabilities { c in {"strings", "regex", "data"} }
    count(input.capabilities) > 0
}
deny_reason = "cloud denied" { "cloud" in input.capabilities }
`

func TestCapabilityGatingEndToEnd(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(capPolicy)})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// A strings builtin is allowed.
	if err := eng.AuthorizeCommand([]string{"starlark.str.split", "arg0=x"}, ""); err != nil {
		t.Fatalf("expected str.split allowed, got: %v", err)
	}

	// A cloud builtin is denied.
	if err := eng.AuthorizeCommand([]string{"starlark.aws.ec2.terminate", "arg0=i-123"}, ""); err == nil {
		t.Fatalf("expected aws.* denied by cloud capability, got allow")
	}
}
