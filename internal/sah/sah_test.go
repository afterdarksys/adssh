package sah

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

type readFlag struct {
	read bool
}

func (r *readFlag) Read(p []byte) (int, error) {
	r.read = true
	return 0, errors.New("should_not_read")
}

func TestHandleDisabledDoesNotReadOrExec(t *testing.T) {
	in := &readFlag{}
	called := false
	var out bytes.Buffer
	code := Handle(false, in, &out, func(command []string) (string, string, int, error) {
		called = true
		return "ran", "", 0, nil
	})
	if code != 2 {
		t.Fatalf("exit %d", code)
	}
	if in.read {
		t.Fatal("disabled switch read stdin")
	}
	if called {
		t.Fatal("disabled switch called exec")
	}
	if !strings.Contains(out.String(), `"error":"sah_disabled"`) {
		t.Fatalf("body %s", out.String())
	}
	if !strings.Contains(out.String(), `"handoff":"not_wired"`) {
		t.Fatalf("body %s", out.String())
	}
}

func TestHandleHelloOnDoesNotExec(t *testing.T) {
	called := false
	var out bytes.Buffer
	code := Handle(true, strings.NewReader("{\"v\":1,\"id\":\"hello1\",\"type\":\"hello\",\"lease_id\":\"lease-abc\"}\n"), &out, func(command []string) (string, string, int, error) {
		called = true
		return "", "", 0, nil
	})
	if code != 0 {
		t.Fatalf("exit %d body %s", code, out.String())
	}
	if called {
		t.Fatal("hello called exec")
	}
	body := out.String()
	for _, want := range []string{`"ok":true`, `"protocol":"sah/1"`, `"handoff":"not_wired"`, `"role":"adssh"`, `"id":"hello1"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s in %s", want, body)
		}
	}
}

func TestHandleExecuteOn(t *testing.T) {
	var got []string
	var out bytes.Buffer
	code := Handle(true, strings.NewReader("{\"v\":1,\"id\":\"ex1\",\"type\":\"execute\",\"command\":[\"/bin/echo\",\"hi\"],\"lease_id\":\"lease-nope\"}\n"), &out, func(command []string) (string, string, int, error) {
		got = append([]string{}, command...)
		return "hi\n", "", 0, nil
	})
	if code != 0 {
		t.Fatalf("exit %d body %s", code, out.String())
	}
	if len(got) != 2 || got[0] != "/bin/echo" || got[1] != "hi" {
		t.Fatalf("exec args %#v", got)
	}
	body := out.String()
	if !strings.Contains(body, `"handoff":"not_wired"`) || !strings.Contains(body, `"exit_code":0`) {
		t.Fatalf("body %s", body)
	}
}

func TestHandleRejectsBeforeExec(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string
	}{
		{"bad json", "{", "bad_frame"},
		{"unknown field", `{"v":1,"id":"a","type":"hello","extra":true}`, "bad_frame"},
		{"version", `{"v":2,"id":"a","type":"hello"}`, "version_rejected"},
		{"bad id", `{"v":1,"id":"","type":"hello"}`, "bad_id"},
		{"bad id chars", `{"v":1,"id":"has space","type":"hello"}`, "bad_id"},
		{"type", `{"v":1,"id":"a","type":"shell"}`, "type_rejected"},
		{"empty command", `{"v":1,"id":"a","type":"execute","command":[]}`, "command_rejected"},
		{"adssh", `{"v":1,"id":"a","type":"execute","command":["/tmp/adssh","sah"]}`, "command_rejected"},
		{"sah", `{"v":1,"id":"a","type":"execute","command":["sah"]}`, "command_rejected"},
		{"vbin", `{"v":1,"id":"a","type":"execute","command":["lease","--from","env:X"]}`, "command_rejected"},
		{"nul", "{\"v\":1,\"id\":\"a\",\"type\":\"execute\",\"command\":[\"echo\",\"a\\u0000b\"]}", "command_rejected"},
		{"too many", `{"v":1,"id":"a","type":"execute","command":["x","1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31","32"]}`, "command_rejected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			var out bytes.Buffer
			code := Handle(true, strings.NewReader(tc.line+"\n"), &out, func(command []string) (string, string, int, error) {
				called = true
				return "", "", 0, nil
			})
			if code != 2 {
				t.Fatalf("exit %d", code)
			}
			if called {
				t.Fatal("exec called")
			}
			if !strings.Contains(out.String(), `"error":"`+tc.want+`"`) {
				t.Fatalf("body %s", out.String())
			}
			if !strings.Contains(out.String(), `"handoff":"not_wired"`) {
				t.Fatalf("body %s", out.String())
			}
		})
	}
}

func TestHandleExecuteUnavailableAndUnsafeError(t *testing.T) {
	var out bytes.Buffer
	code := Handle(true, strings.NewReader(`{"v":1,"id":"a","type":"execute","command":["/bin/echo"]}`+"\n"), &out, nil)
	if code != 2 || !strings.Contains(out.String(), `"error":"execute_unavailable"`) {
		t.Fatalf("nil exec: %d %s", code, out.String())
	}
	out.Reset()
	code = Handle(true, strings.NewReader(`{"v":1,"id":"a","type":"execute","command":["/bin/echo"]}`+"\n"), &out, func(command []string) (string, string, int, error) {
		return "secret-token", "boom raw", 7, errors.New("open /etc/shadow: permission denied")
	})
	if code != 2 {
		t.Fatalf("exit %d", code)
	}
	body := out.String()
	if !strings.Contains(body, `"error":"execute_failed"`) {
		t.Fatalf("body %s", body)
	}
	if strings.Contains(body, "shadow") || strings.Contains(body, "secret-token") {
		t.Fatalf("leaked %s", body)
	}
}

func TestHandleFixedErrorAndOutputCap(t *testing.T) {
	var out bytes.Buffer
	code := Handle(true, strings.NewReader(`{"v":1,"id":"a","type":"execute","command":["/bin/echo"]}`+"\n"), &out, func(command []string) (string, string, int, error) {
		return "", "", 0, errors.New("policy_required")
	})
	if code != 2 || !strings.Contains(out.String(), `"error":"policy_required"`) {
		t.Fatalf("body %s", out.String())
	}
	out.Reset()
	big := strings.Repeat("A", maxOutput+50)
	code = Handle(true, strings.NewReader(`{"v":1,"id":"a","type":"execute","command":["/bin/echo"]}`+"\n"), &out, func(command []string) (string, string, int, error) {
		return big, big, 3, nil
	})
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if strings.Count(out.String(), "A") != maxOutput*2 {
		t.Fatalf("cap failed: %d A's", strings.Count(out.String(), "A"))
	}
	if !strings.Contains(out.String(), `"exit_code":3`) {
		t.Fatalf("body %s", out.String())
	}
}

func TestHandleTooLargeDoesNotExec(t *testing.T) {
	called := false
	var out bytes.Buffer
	payload := strings.Repeat("x", maxFrame+10) + "\n"
	code := Handle(true, strings.NewReader(payload), &out, func(command []string) (string, string, int, error) {
		called = true
		return "", "", 0, nil
	})
	if code != 2 || called || !strings.Contains(out.String(), `"error":"too_large"`) {
		t.Fatalf("code %d called %v body %s", code, called, out.String())
	}
}

func TestReadFrameNil(t *testing.T) {
	var out bytes.Buffer
	code := Handle(true, nil, &out, nil)
	if code != 2 || !strings.Contains(out.String(), "bad_frame") {
		t.Fatalf("code %d body %s", code, out.String())
	}
	if _, err := readFrame(strings.NewReader("")); err != io.EOF {
		t.Fatalf("empty: %v", err)
	}
}
