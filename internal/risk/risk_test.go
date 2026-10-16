package risk

import "testing"

func TestShellCommandClass(t *testing.T) {
	cases := map[string]string{
		"rm -rf /tmp/x":                "destructive",
		"RM -RF /tmp/x":                "destructive",
		"kubectl delete pod web-1":     "destructive",
		"git push --force origin main": "destructive",
		"terraform destroy":            "destructive",
		"aws.ec2.terminate(ids=[1])":   "destructive",
		"chmod 777 /srv":               "destructive",
		"ls -la":                       "mutable",
		"kubectl get pods":             "mutable",
		"git push origin main":         "mutable",
		"":                             "mutable",
	}
	for cmd, want := range cases {
		if got := ShellCommandClass(cmd); got != want {
			t.Errorf("ShellCommandClass(%q) = %q, want %q", cmd, got, want)
		}
		if got := LooksDestructive(cmd); got != (want == "destructive") {
			t.Errorf("LooksDestructive(%q) = %v", cmd, got)
		}
	}
}
