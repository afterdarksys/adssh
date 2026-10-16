package parser

import (
	"strings"
	"testing"
)

func TestClassifyFlowForms(t *testing.T) {
	cases := []struct {
		name string
		src  string
		kind FlowKind
		err  string
		op   string
	}{
		{name: "try catch", src: "try { echo hi } catch { echo ok }", kind: FlowReady, op: "try"},
		{name: "try catch tight", src: "try{echo hi}catch{echo ok}", kind: FlowReady, op: "try"},
		{name: "if else", src: "if true { echo yes } else { echo no }", kind: FlowReady, op: "if"},
		{name: "if else tight", src: "if true{echo yes}else{echo no}", kind: FlowReady, op: "if"},
		{name: "if no else", src: "if true { echo hi }", kind: FlowReady, op: "if"},
		{name: "quoted brace", src: `try { echo "a { b" } catch { echo ok }`, kind: FlowReady, op: "try"},
		{name: "single quoted brace", src: "try { echo 'a { b' } catch { echo ok }", kind: FlowReady, op: "try"},
		{name: "comment between", src: "try { echo hi } # note\ncatch { echo ok }", kind: FlowReady, op: "try"},
		{name: "nested group", src: "try { { echo hi; } } catch { echo ok }", kind: FlowReady, op: "try"},
		{name: "quoted then is brace", src: `if echo "then" { echo hi }`, kind: FlowReady, op: "if"},
		{name: "then inside body is brace", src: "if true { echo then }", kind: FlowReady, op: "if"},
		{name: "posix then", src: "if true; then echo yes; fi", kind: FlowNot},
		{name: "posix then before brace", src: "if true; then { echo; } fi", kind: FlowNot},
		{name: "posix fi", src: "if true; then echo yes; else echo no; fi", kind: FlowNot},
		{name: "starlark colon", src: "if x > 5:", kind: FlowNot},
		{name: "starlark colon comment", src: "if x > 5:  # keep", kind: FlowNot},
		{name: "starlark dict", src: "if True:\n  x = {1: 2}", kind: FlowNot},
		{name: "colon before brace", src: "if x > 5: { echo hi }", kind: FlowNot},
		{name: "tryout", src: "tryout { echo hi }", kind: FlowNot},
		{name: "ifconfig", src: "ifconfig", kind: FlowNot},
		{name: "bare try", src: "try", kind: FlowNot},
		{name: "try foo", src: "try foo", kind: FlowNot},
		{name: "partial if", src: "if true", kind: FlowNot},
		{name: "echo", src: "echo hi", kind: FlowNot},
		{name: "needs catch", src: "try { echo hi }", kind: FlowIncomplete, err: "flow: try needs catch"},
		{name: "needs catch comment", src: "try { echo hi } # later\n", kind: FlowIncomplete, err: "flow: try needs catch"},
		{name: "expected catch", src: "try { echo hi } echo", kind: FlowSyntax, err: "flow: expected catch"},
		{name: "unclosed", src: "try { echo hi", kind: FlowIncomplete, err: "flow: unclosed block"},
		{name: "unclosed quote", src: "try { echo \"a { b } catch { echo ok }", kind: FlowIncomplete, err: "flow: unclosed block"},
		{name: "unclosed else", src: "if true { echo hi } else", kind: FlowIncomplete, err: "flow: unclosed block"},
		{name: "empty try", src: "try { } catch { echo ok }", kind: FlowSyntax, err: "flow: empty try body"},
		{name: "comment try", src: "try { # only\n } catch { echo ok }", kind: FlowSyntax, err: "flow: empty try body"},
		{name: "empty catch", src: "try { echo hi } catch { }", kind: FlowSyntax, err: "flow: empty catch body"},
		{name: "empty then", src: "if true { } else { echo no }", kind: FlowSyntax, err: "flow: empty then body"},
		{name: "empty else", src: "if true { echo yes } else { }", kind: FlowSyntax, err: "flow: empty else body"},
		{name: "empty cond", src: "if{ echo hi }", kind: FlowSyntax, err: "flow: empty condition"},
		{name: "empty cond spaces", src: "if { echo hi }", kind: FlowSyntax, err: "flow: empty condition"},
		{name: "if brace glued cond", src: "if{true}{echo}", kind: FlowSyntax, err: "flow: empty condition"},
		{name: "trailing if", src: "if true { echo hi } echo", kind: FlowSyntax, err: "flow: trailing input"},
		{name: "trailing try", src: "try { echo hi } catch { echo ok } echo", kind: FlowSyntax, err: "flow: trailing input"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyFlow(tc.src)
			if got.Kind != tc.kind {
				t.Fatalf("kind %v want %v err %v", got.Kind, tc.kind, got.Err)
			}
			if tc.err != "" {
				if got.Err == nil || got.Err.Error() != tc.err {
					t.Fatalf("err %v want %s", got.Err, tc.err)
				}
			} else if tc.kind == FlowReady || tc.kind == FlowNot {
				if got.Err != nil {
					t.Fatalf("unexpected err %v", got.Err)
				}
			}
			if tc.op != "" && got.Op != tc.op {
				t.Fatalf("op %q", got.Op)
			}
		})
	}
}

func TestClassifyFlowBodies(t *testing.T) {
	got := ClassifyFlow(`try { echo "a { b" } catch { echo ok }`)
	if got.Kind != FlowReady {
		t.Fatal(got.Err)
	}
	if !strings.Contains(got.Try, `echo "a { b"`) || !strings.Contains(got.Catch, "echo ok") {
		t.Fatalf("bodies try %q catch %q", got.Try, got.Catch)
	}
	iff := ClassifyFlow(`if echo "then" { echo hi }`)
	if iff.Kind != FlowReady || iff.HasElse || !strings.Contains(iff.Cond, "then") || !strings.Contains(iff.Then, "echo hi") {
		t.Fatalf("if %+v", iff)
	}
	els := ClassifyFlow("if false { echo yes }else{ echo no }")
	if !els.HasElse || !strings.Contains(els.Else, "echo no") {
		t.Fatalf("else %+v", els)
	}
}

func TestClassifyFlowCaps(t *testing.T) {
	big := strings.Repeat("a", MaxChunkBytes+1)
	got := ClassifyFlow(big)
	if got.Kind != FlowSyntax || got.Err == nil || got.Err.Error() != "flow: input exceeds 1 MiB" {
		t.Fatalf("big %+v", got.Err)
	}
	lines := strings.Repeat("echo\n", MaxChunkLines+1)
	got = ClassifyFlow(lines)
	if got.Kind != FlowSyntax || got.Err == nil || got.Err.Error() != "flow: input exceeds 256 lines" {
		t.Fatalf("lines %v", got.Err)
	}
	okLines := strings.Repeat("echo\n", MaxChunkLines)
	if chunkLineCount(okLines) != MaxChunkLines {
		t.Fatalf("count %d", chunkLineCount(okLines))
	}
}

func TestClassifyChunk(t *testing.T) {
	ready := ClassifyChunk("try { false } catch { echo caught }")
	if ready.Kind != ChunkReady || ready.Mode != ModeShell {
		t.Fatalf("ready %+v", ready)
	}
	more := ClassifyChunk("try {")
	if more.Kind != ChunkNeedMore || more.Err == nil || more.Err.Error() != "flow: unclosed block" {
		t.Fatalf("more %+v", more)
	}
	syn := ClassifyChunk("try { } catch { echo x }")
	if syn.Kind != ChunkSyntax || syn.Err == nil || syn.Err.Error() != "flow: empty try body" {
		t.Fatalf("syn %+v", syn)
	}
	star := ClassifyChunk("if x > 5:")
	if star.Kind != ChunkReady || star.Mode != ModeStarlark {
		t.Fatalf("star %+v", star)
	}
	posix := ClassifyChunk("if true; then")
	if posix.Kind != ChunkNeedMore || posix.Mode != ModeShell {
		t.Fatalf("posix %+v err %v", posix.Kind, posix.Err)
	}
	done := ClassifyChunk("if true; then echo yes; fi")
	if done.Kind != ChunkReady || done.Mode != ModeShell {
		t.Fatalf("done %+v", done)
	}
	hard := ClassifyChunk("echo )")
	if hard.Kind != ChunkReady || ShellIncomplete("echo )") {
		t.Fatalf("hard syntax treated as incomplete: %+v", hard)
	}
}

func TestShellIncomplete(t *testing.T) {
	if !ShellIncomplete("if true; then") {
		t.Fatal("posix if should be incomplete")
	}
	if ShellIncomplete("if true; then echo yes; fi") {
		t.Fatal("closed posix if")
	}
	if ShellIncomplete("echo )") {
		t.Fatal("hard error is not incomplete")
	}
	if !ShellIncomplete("! if true; then") {
		t.Fatal("forced shell prefix")
	}
}

func TestStarlarkIfWithBraceLiteralStaysStarlark(t *testing.T) {
	for _, src := range []string{
		`if d == {}: print("empty")`,
		`if x in {1, 2}:`,
		`if d == {"a": 1}:`,
		"if d == {\"a\": 1}:\n  print(\"one\")",
		`if x == [{"a": 1}]:`,
		"if d == {\n  \"a\": 1,\n}:",
	} {
		t.Run(src, func(t *testing.T) {
			if got := ClassifyFlow(src); got.Kind != FlowNot || got.Err != nil {
				t.Fatalf("flow kind %v err %v", got.Kind, got.Err)
			}
			if c := ClassifyChunk(src); c.Kind != ChunkReady || c.Mode != ModeStarlark {
				t.Fatalf("chunk %+v", c)
			}
		})
	}
}

func TestShellBraceIfStillFlow(t *testing.T) {
	for _, src := range []string{
		"if true { echo yes }",
		"if true { echo yes } else { echo no }",
		"if [ -f x ] { echo yes }",
		"if test -n \"$(echo {)\" { echo yes }",
		"if ls a[0-9] { echo yes }",
		"if (true) { echo yes }",
		"if true {\n  echo a:\n}",
	} {
		t.Run(src, func(t *testing.T) {
			got := ClassifyFlow(src)
			if got.Kind != FlowReady || got.Op != "if" {
				t.Fatalf("kind %v err %v", got.Kind, got.Err)
			}
		})
	}
	if got := ClassifyFlow("if true {"); got.Kind != FlowIncomplete {
		t.Fatalf("open brace kind %v", got.Kind)
	}
}
