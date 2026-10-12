package starlarkext

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.starlark.net/starlark"
)

func callNet(t *testing.T, name string, fn func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error), args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	t.Helper()
	b := starlark.NewBuiltin(name, fn)
	return starlark.Call(&starlark.Thread{Name: "net-tls"}, b, args, kwargs)
}

func TestSkipVerifyRefusedWithNoNetwork(t *testing.T) {
	t.Setenv("ADSSH_ALLOW_INSECURE_TLS", "1")
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	_, err := callNet(t, "http_get", builtinHTTPGet, starlark.Tuple{starlark.String(srv.URL)}, []starlark.Tuple{{starlark.String("skip_verify"), starlark.True}})
	if err == nil || !strings.Contains(err.Error(), "skip_verify is refused") {
		t.Fatalf("http_get skip_verify: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("http_get dialed despite skip_verify")
	}

	val, err := callNet(t, "http_get", builtinHTTPGet, starlark.Tuple{starlark.String(srv.URL)}, nil)
	if err != nil {
		t.Fatalf("plain http_get: %v", err)
	}
	if val.String() != `"ok"` {
		t.Fatalf("plain http_get body = %s", val.String())
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("secret"))
	}))
	defer ts.Close()
	_, err = callNet(t, "http_get", builtinHTTPGet, starlark.Tuple{starlark.String(ts.URL)}, nil)
	if err == nil || strings.Contains(err.Error(), "skip_verify") {
		t.Fatalf("untrusted TLS result = %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	go func() {
		c, accErr := ln.Accept()
		if accErr == nil {
			accepted.Add(1)
			c.Close()
		}
	}()
	addr := ln.Addr().String()
	_, err = callNet(t, "dial_tls", builtinDialTLS, starlark.Tuple{starlark.String(addr)}, []starlark.Tuple{{starlark.String("skip_verify"), starlark.True}})
	if err == nil || !strings.Contains(err.Error(), "skip_verify is refused") {
		t.Fatalf("dial_tls skip_verify: %v", err)
	}
	_, err = callNet(t, "tcp_send", builtinTCPSend,
		starlark.Tuple{starlark.String(addr), starlark.String("hi")},
		[]starlark.Tuple{{starlark.String("use_tls"), starlark.True}, {starlark.String("skip_verify"), starlark.True}})
	if err == nil || !strings.Contains(err.Error(), "skip_verify is refused") {
		t.Fatalf("tcp_send skip_verify: %v", err)
	}
	ln.Close()
	time.Sleep(20 * time.Millisecond)
	if accepted.Load() != 0 {
		t.Fatal("skip_verify dialed the listener")
	}
}
