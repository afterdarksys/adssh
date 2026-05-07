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

func builtinHTTPGet(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var url string
	var skipVerify bool
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "url", &url, "skip_verify?", &skipVerify); err != nil {
		return nil, err
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("http_get error: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return starlark.String(string(body)), nil
}

func builtinTCPSend(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var addr, data string
	var useTLS bool
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "addr", &addr, "data", &data, "use_tls?", &useTLS); err != nil {
		return nil, err
	}

	var conn net.Conn
	var err error
	if useTLS {
		conn, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
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

	// Read response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, _ := io.ReadAll(conn)
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
	var skipVerify bool = false
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "address", &addr, "skip_verify?", &skipVerify); err != nil {
		return nil, err
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: skipVerify})
	if err != nil {
		return nil, fmt.Errorf("dial_tls error: %v", err)
	}

	return &StarlarkConn{Conn: conn}, nil
}
