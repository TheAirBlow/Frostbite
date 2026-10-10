package edge

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"frostbite/internal/spec"
)

// backend accepts one connection and reports the server name in the hello it received, plus the first bytes.
func backend(t *testing.T) (addr string, got chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
				h, _, err := peekHello(c)
				if err != nil {
					got <- "no-hello"
					return
				}
				got <- h.ServerName
			}()
		}
	}()
	return ln.Addr().String(), got
}

// hello makes a client send a hello for name and then gives up.
func hello(t *testing.T, addr, name string, alpn ...string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_ = tls.Client(c, &tls.Config{ServerName: name, NextProtos: alpn, InsecureSkipVerify: true}).Handshake()
}

func start(t *testing.T, e spec.Edge) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	e.Listen = []string{addr}
	r := New()
	if err := r.Apply(context.Background(), spec.Daemon{Kind: "edge", Edge: &e}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return addr
}

func expect(t *testing.T, got chan string, want string) {
	t.Helper()
	select {
	case v := <-got:
		if v != want {
			t.Fatalf("backend saw %q, want %q", v, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("backend never saw %q", want)
	}
}

func TestRoutesBySNIAndKeepsTheHelloIntact(t *testing.T) {
	a, gotA := backend(t)
	b, gotB := backend(t)
	def, gotDef := backend(t)

	addr := start(t, spec.Edge{
		Routes:  []spec.EdgeRoute{{Name: "a", SNI: []string{"a.example.com"}, Target: a}, {Name: "b", SNI: []string{"*.cdn.example.com"}, Target: b}},
		Default: def,
	})

	hello(t, addr, "a.example.com")
	expect(t, gotA, "a.example.com")
	hello(t, addr, "edge1.cdn.example.com")
	expect(t, gotB, "edge1.cdn.example.com")
	hello(t, addr, "unknown.example.org")
	expect(t, gotDef, "unknown.example.org")
}

func TestALPNNarrowsARoute(t *testing.T) {
	h2, gotH2 := backend(t)
	any, gotAny := backend(t)
	addr := start(t, spec.Edge{Routes: []spec.EdgeRoute{
		{Name: "h2", SNI: []string{"x.example.com"}, ALPN: []string{"h2"}, Target: h2},
		{Name: "rest", SNI: []string{"x.example.com"}, Target: any},
	}})

	hello(t, addr, "x.example.com", "h2", "http/1.1")
	expect(t, gotH2, "x.example.com")
	hello(t, addr, "x.example.com", "http/1.1")
	expect(t, gotAny, "x.example.com")
}

func TestPlainTrafficGoesToTheDefault(t *testing.T) {
	def, gotDef := backend(t)
	addr := start(t, spec.Edge{Default: def})

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: probe\r\n\r\n"))
	expect(t, gotDef, "no-hello")
}

func TestNoDefaultDropsUnmatched(t *testing.T) {
	addr := start(t, spec.Edge{})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Write([]byte{0x16, 0x03, 0x01})
	buf := make([]byte, 1)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("an unmatched connection should be closed")
	}
}

func TestProxyHeaderCarriesTheClient(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 40000}
	dst := &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443}
	h := proxyHeader(src, dst)

	if string(h[:4]) != "\r\n\r\n" || h[12] != 0x21 || h[13] != 0x11 {
		t.Fatalf("not a v2 tcp4 header: %x", h[:16])
	}
	if binary.BigEndian.Uint16(h[14:16]) != 12 {
		t.Fatal("length should be 12 for ipv4")
	}
	if net.IP(h[16:20]).String() != "203.0.113.9" || binary.BigEndian.Uint16(h[24:26]) != 40000 {
		t.Fatal("source address or port is wrong")
	}
}

func TestMatchName(t *testing.T) {
	if !matchName([]string{"*.example.com"}, "a.b.example.com") || matchName([]string{"*.example.com"}, "example.com") || matchName([]string{"a.com"}, "") {
		t.Fatal("wildcards cover subdomains, not the apex, and empty names never match")
	}
}
