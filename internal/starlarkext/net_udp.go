package starlarkext

// net.dial_udp(host, port, data, timeout=5) -> str: send one datagram and
// return the first reply.
//
// It sits next to net.dial and is gated the same way: the govern wrapper
// authorizes starlark.net.dial_udp under the `net` namespace capabilities
// before any packet is sent, and the namespace is omitted in restricted
// sessions.
//
// Threats:
//   - Ungoverned egress. Gated by the govern wrapper like net.dial; this file
//     adds no bypass and no broadcast or listen mode.
//   - Hangs. The timeout (1..60 s) bounds the whole exchange; no reply by
//     then is an error, never an empty success.
//   - Oversized payloads. The request is capped at maxUDPBytes and the reply
//     buffer holds maxUDPBytes+1, so a reply over the cap fails the call
//     instead of being silently truncated.
// It does not authenticate the peer: a UDP reply can be spoofed by anyone on
// the path. Do not treat the reply as trusted.

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"go.starlark.net/starlark"
)

const (
	maxUDPBytes      = 64 << 10
	maxUDPTimeoutSec = 60
)

func builtinDialUDP(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var host, data string
	var port int
	timeoutSecs := 5
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "host", &host, "port", &port, "data", &data, "timeout?", &timeoutSecs); err != nil {
		return nil, err
	}
	if host == "" {
		return nil, fmt.Errorf("dial_udp: host is required")
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("dial_udp: port must be between 1 and 65535")
	}
	if timeoutSecs < 1 || timeoutSecs > maxUDPTimeoutSec {
		return nil, fmt.Errorf("dial_udp: timeout must be between 1 and %d seconds", maxUDPTimeoutSec)
	}
	if len(data) > maxUDPBytes {
		return nil, fmt.Errorf("dial_udp: data exceeds %d bytes", maxUDPBytes)
	}
	timeout := time.Duration(timeoutSecs) * time.Second
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return nil, fmt.Errorf("dial_udp error: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("dial_udp deadline error: %v", err)
	}
	if _, err := conn.Write([]byte(data)); err != nil {
		return nil, fmt.Errorf("dial_udp write error: %v", err)
	}
	buf := make([]byte, maxUDPBytes+1)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("dial_udp read error: %v", err)
	}
	if n > maxUDPBytes {
		return nil, fmt.Errorf("dial_udp: response exceeds %d bytes", maxUDPBytes)
	}
	return starlark.String(string(buf[:n])), nil
}
