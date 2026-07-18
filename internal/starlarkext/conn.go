package starlarkext

import (
	"fmt"
	"io"
	"net"
	"time"

	"go.starlark.net/starlark"
)

// StarlarkConn wraps a net.Conn to expose it to the Starlark environment.
type StarlarkConn struct {
	Conn net.Conn
}

var _ starlark.Value = (*StarlarkConn)(nil)
var _ starlark.HasAttrs = (*StarlarkConn)(nil)

func (c *StarlarkConn) String() string {
	return fmt.Sprintf("<net.Conn %s -> %s>", c.Conn.LocalAddr(), c.Conn.RemoteAddr())
}

func (c *StarlarkConn) Type() string {
	return "net.Conn"
}

func (c *StarlarkConn) Freeze() {
	// Sockets cannot be frozen
}

func (c *StarlarkConn) Truth() starlark.Bool {
	return c.Conn != nil
}

func (c *StarlarkConn) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable type: net.Conn")
}

func (c *StarlarkConn) Attr(name string) (starlark.Value, error) {
	switch name {
	case "read":
		return starlark.NewBuiltin("read", c.builtinRead), nil
	case "read_all":
		return starlark.NewBuiltin("read_all", c.builtinReadAll), nil
	case "write":
		return starlark.NewBuiltin("write", c.builtinWrite), nil
	case "close":
		return starlark.NewBuiltin("close", c.builtinClose), nil
	default:
		return nil, nil // No such attribute
	}
}

func (c *StarlarkConn) AttrNames() []string {
	return []string{"read", "read_all", "write", "close"}
}

func (c *StarlarkConn) builtinRead(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var n = 1024 // Default buffer size
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "n?", &n); err != nil {
		return nil, err
	}

	buf := make([]byte, n)
	_ = c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // best-effort: a failed deadline surfaces on the read itself
	readBytes, err := c.Conn.Read(buf)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("read error: %v", err)
	}

	return starlark.String(string(buf[:readBytes])), nil
}

func (c *StarlarkConn) builtinReadAll(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // best-effort: a failed deadline surfaces on the read itself
	data, err := io.ReadAll(c.Conn)
	if err != nil {
		return nil, fmt.Errorf("read_all error: %v", err)
	}
	return starlark.String(string(data)), nil
}

func (c *StarlarkConn) builtinWrite(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "data", &data); err != nil {
		return nil, err
	}

	_ = c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second)) // best-effort: a failed deadline surfaces on the write itself
	wroteBytes, err := c.Conn.Write([]byte(data))
	if err != nil {
		return nil, fmt.Errorf("write error: %v", err)
	}

	return starlark.MakeInt(wroteBytes), nil
}

func (c *StarlarkConn) builtinClose(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	err := c.Conn.Close()
	if err != nil {
		return nil, fmt.Errorf("close error: %v", err)
	}
	return starlark.None, nil
}
