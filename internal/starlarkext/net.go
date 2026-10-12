package starlarkext

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"go.starlark.net/starlark"
)

// Threats: a caller-supplied skip_verify disables certificate checks and
// allows a network MITM. These builtins refuse that flag before any dial.
// They do not pin certificates or replace the system root pool. Responses
// larger than maxNetRead are rejected.
const maxNetRead = 1 << 20

func refuseSkipVerify(skip bool) error {
	if skip {
		return fmt.Errorf("skip_verify is refused")
	}
	return nil
}

func tls13Config() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13}
}

func readNetCapped(r io.Reader, what string) (string, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxNetRead+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxNetRead {
		return "", fmt.Errorf("%s: response exceeds %d bytes", what, maxNetRead)
	}
	return string(body), nil
}

func builtinHTTPGet(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var url string
	var skipVerify bool
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "url", &url, "skip_verify?", &skipVerify); err != nil {
		return nil, err
	}
	if err := refuseSkipVerify(skipVerify); err != nil {
		return nil, err
	}

	tr := &http.Transport{TLSClientConfig: tls13Config()}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("http_get error: %v", err)
	}
	defer resp.Body.Close()
	body, err := readNetCapped(resp.Body, "http_get")
	if err != nil {
		return nil, err
	}
	return starlark.String(body), nil
}

func builtinTCPSend(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var addr, data string
	var useTLS, skipVerify bool
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "addr", &addr, "data", &data, "use_tls?", &useTLS, "skip_verify?", &skipVerify); err != nil {
		return nil, err
	}
	if err := refuseSkipVerify(skipVerify); err != nil {
		return nil, err
	}

	var conn net.Conn
	var err error
	if useTLS {
		conn, err = tls.Dial("tcp", addr, tls13Config())
	} else {
		conn, err = net.DialTimeout("tcp", addr, 5*time.Second)
	}
	if err != nil {
		return nil, fmt.Errorf("tcp connect error: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(data)); err != nil {
		return nil, fmt.Errorf("tcp write error: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, fmt.Errorf("tcp deadline error: %v", err)
	}
	limited := io.LimitReader(conn, maxNetRead+1)
	resp, readErr := io.ReadAll(limited)
	if len(resp) > maxNetRead {
		return nil, fmt.Errorf("tcp_send: response exceeds %d bytes", maxNetRead)
	}
	if readErr != nil && len(resp) == 0 {
		return nil, fmt.Errorf("tcp read error: %v", readErr)
	}
	return starlark.String(string(resp)), nil
}

func builtinDial(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var network, addr string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "network", &network, "address", &addr); err != nil {
		return nil, err
	}

	conn, err := net.DialTimeout(network, addr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial error: %v", err)
	}

	return &StarlarkConn{Conn: conn}, nil
}

func builtinDialTLS(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var addr string
	var skipVerify bool
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "address", &addr, "skip_verify?", &skipVerify); err != nil {
		return nil, err
	}
	if err := refuseSkipVerify(skipVerify); err != nil {
		return nil, err
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, tls13Config())
	if err != nil {
		return nil, fmt.Errorf("dial_tls error: %v", err)
	}

	return &StarlarkConn{Conn: conn}, nil
}
