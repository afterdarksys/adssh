package starlarkext

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"time"

	"github.com/creack/pty"
	"go.starlark.net/starlark"
)

// SetupExpectAPI registers the expect.* namespace into the Starlark environment.
//
// Starlark API:
//
//	proc = expect.spawn("ssh", args=["user@host"], timeout=30)
//	proc.sendline("password")
//	out = proc.expect("\\$", timeout=10)   # returns text up to and including match
//	out = proc.expect_exact("login:", timeout=10)
//	proc.send("raw text no newline")
//	proc.sendcontrol("c")                  # sends ^C (also "d", "z", etc.)
//	all = proc.output()                    # all buffered output so far
//	proc.close()
func SetupExpectAPI(env starlark.StringDict) {
	d := starlark.NewDict(1)
	d.SetKey(starlark.String("spawn"), starlark.NewBuiltin("spawn", expectSpawn))
	env["expect"] = d
}

// expectProc is a live PTY-backed process exposed as a Starlark value.
type expectProc struct {
	ptmx           *os.File
	cmd            *exec.Cmd
	mu             sync.Mutex
	buf            bytes.Buffer
	closed         bool
	defaultTimeout time.Duration
}

var _ starlark.HasAttrs = (*expectProc)(nil)

func (p *expectProc) String() string        { return "<expect.proc>" }
func (p *expectProc) Type() string          { return "expect.proc" }
func (p *expectProc) Freeze()               {}
func (p *expectProc) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: expect.proc") }
func (p *expectProc) Truth() starlark.Bool  { return starlark.Bool(!p.closed) }

func (p *expectProc) Attr(name string) (starlark.Value, error) {
	switch name {
	case "send":
		return starlark.NewBuiltin("send", p.builtinSend), nil
	case "sendline":
		return starlark.NewBuiltin("sendline", p.builtinSendLine), nil
	case "expect":
		return starlark.NewBuiltin("expect", p.builtinExpect), nil
	case "expect_exact":
		return starlark.NewBuiltin("expect_exact", p.builtinExpectExact), nil
	case "sendcontrol":
		return starlark.NewBuiltin("sendcontrol", p.builtinSendControl), nil
	case "close":
		return starlark.NewBuiltin("close", p.builtinClose), nil
	case "output":
		return starlark.NewBuiltin("output", p.builtinOutput), nil
	}
	return nil, nil
}

func (p *expectProc) AttrNames() []string {
	return []string{"close", "expect", "expect_exact", "output", "send", "sendcontrol", "sendline"}
}

// readInto continuously drains the PTY master into the buffer.
func (p *expectProc) readInto() {
	tmp := make([]byte, 4096)
	for {
		n, err := p.ptmx.Read(tmp)
		if n > 0 {
			p.mu.Lock()
			p.buf.Write(tmp[:n])
			p.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func expectSpawn(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var cmdStr string
	var cmdArgs *starlark.List
	var timeout float64 = 30
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "cmd", &cmdStr, "args?", &cmdArgs, "timeout?", &timeout); err != nil {
		return nil, err
	}

	argv := []string{}
	if cmdArgs != nil {
		for i := 0; i < cmdArgs.Len(); i++ {
			s, ok := starlark.AsString(cmdArgs.Index(i))
			if !ok {
				return nil, fmt.Errorf("spawn: args elements must be strings")
			}
			argv = append(argv, s)
		}
	}

	cmd := exec.Command(cmdStr, argv...)
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("expect.spawn: %v", err)
	}

	proc := &expectProc{
		ptmx:           ptmx,
		cmd:            cmd,
		defaultTimeout: time.Duration(float64(time.Second) * timeout),
	}
	go proc.readInto()
	return proc, nil
}

func (p *expectProc) builtinSend(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "text", &text); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(p.ptmx, text); err != nil {
		return nil, fmt.Errorf("send: %v", err)
	}
	return starlark.None, nil
}

func (p *expectProc) builtinSendLine(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "text", &text); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(p.ptmx, text+"\r\n"); err != nil {
		return nil, fmt.Errorf("sendline: %v", err)
	}
	return starlark.None, nil
}

// builtinExpect waits until the buffer matches the given regex pattern, then
// returns all buffered text up to and including the match. Consumed bytes are
// removed from the buffer.
func (p *expectProc) builtinExpect(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pattern string
	var timeout float64 = -1
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "pattern", &pattern, "timeout?", &timeout); err != nil {
		return nil, err
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("expect: invalid pattern: %v", err)
	}
	d := p.defaultTimeout
	if timeout >= 0 {
		d = time.Duration(float64(time.Second) * timeout)
	}
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		data := p.buf.Bytes()
		loc := re.FindIndex(data)
		if loc != nil {
			matched := string(data[:loc[1]])
			tail := make([]byte, len(data)-loc[1])
			copy(tail, data[loc[1]:])
			p.buf.Reset()
			p.buf.Write(tail)
			p.mu.Unlock()
			return starlark.String(matched), nil
		}
		p.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	return nil, fmt.Errorf("expect: timeout after %v waiting for %q", d, pattern)
}

// builtinExpectExact waits for an exact substring match.
func (p *expectProc) builtinExpectExact(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	var timeout float64 = -1
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "text", &text, "timeout?", &timeout); err != nil {
		return nil, err
	}
	needle := []byte(text)
	d := p.defaultTimeout
	if timeout >= 0 {
		d = time.Duration(float64(time.Second) * timeout)
	}
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		data := p.buf.Bytes()
		idx := bytes.Index(data, needle)
		if idx >= 0 {
			end := idx + len(needle)
			matched := string(data[:end])
			tail := make([]byte, len(data)-end)
			copy(tail, data[end:])
			p.buf.Reset()
			p.buf.Write(tail)
			p.mu.Unlock()
			return starlark.String(matched), nil
		}
		p.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	return nil, fmt.Errorf("expect_exact: timeout after %v waiting for %q", d, text)
}

// builtinSendControl sends a control character. "c" sends ^C (byte 3), "d"
// sends ^D (byte 4), etc. Accepts both upper and lower case.
func (p *expectProc) builtinSendControl(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var char string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "char", &char); err != nil {
		return nil, err
	}
	if len(char) != 1 {
		return nil, fmt.Errorf("sendcontrol: char must be a single letter (a-z)")
	}
	c := char[0]
	if c >= 'A' && c <= 'Z' {
		c = c - 'A' + 1
	} else if c >= 'a' && c <= 'z' {
		c = c - 'a' + 1
	} else {
		return nil, fmt.Errorf("sendcontrol: char must be a letter a-z or A-Z")
	}
	if _, err := p.ptmx.Write([]byte{c}); err != nil {
		return nil, fmt.Errorf("sendcontrol: %v", err)
	}
	return starlark.None, nil
}

func (p *expectProc) builtinClose(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.ptmx.Close()
		if p.cmd.Process != nil {
			p.cmd.Process.Kill()
		}
		p.closed = true
	}
	return starlark.None, nil
}

func (p *expectProc) builtinOutput(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return starlark.String(p.buf.String()), nil
}
