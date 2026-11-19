package agent

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

// pickyTarget is a TLS 1.3 server with h2 that hangs up on a hello that carries no server name, the way a
// default-reject virtual host does.
func pickyTarget(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := selfSigned(dir+"/c.pem", dir+"/k.pem", "example.test"); err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(dir+"/c.pem", dir+"/k.pem")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, Certificates: []tls.Certificate{cert}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				conf := cfg.Clone()
				conf.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
					if h.ServerName == "" {
						_ = c.Close() // hang up without an alert, which the client sees as a reset
						return nil, net.ErrClosed
					}
					return cfg, nil
				}
				srv := tls.Server(c, conf)
				_ = srv.Handshake()
			}()
		}
	}()
	return ln.Addr().String()
}

func TestHandshakeProbeSendsTheServerNameItWasGiven(t *testing.T) {
	dest := pickyTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := testTLS(ctx, dest, "", 0); err == nil {
		t.Fatal("a target that wants a server name must refuse a probe without one")
	} else if !strings.Contains(err.Error(), "Server names") {
		t.Fatalf("the failure should explain itself, got: %v", err)
	}

	out, err := testTLS(ctx, dest, "example.test", 0)
	if err != nil {
		t.Fatalf("with the server name it must pass: %v", err)
	}
	if !strings.Contains(out, "TLS 1.3") {
		t.Fatalf("unexpected report %q", out)
	}
}

func TestHandshakeProbeExplainsARefusedPort(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()
	_, err := testTLS(context.Background(), addr, "example.test", 0)
	if err == nil || !strings.Contains(err.Error(), "nothing is listening") {
		t.Fatalf("got %v", err)
	}
}
