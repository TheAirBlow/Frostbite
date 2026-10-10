//go:build !race

// These tests drive real connections across user updates. The race detector is excluded on purpose: sing-box's services
// replace their user maps without locking. The writes are single words and maps are swapped, never edited, so readers see
// the old or the new table, but the detector rightly cannot know that.

package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/proxy"

	"frostbite/internal/core"
	_ "frostbite/internal/core/singbox"
	"frostbite/internal/spec"
)

// freePort finds a port nothing listens on.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// echo starts a tcp server that sends back what it reads.
func echo(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}

// client runs a sing-box that exposes a socks port and sends everything to the vless server as the given user.
func client(t *testing.T, serverPort int, out map[string]any) (socks string) {
	t.Helper()
	port := freePort(t)
	cfg := map[string]any{
		"log":       map[string]any{"level": "error"},
		"inbounds":  []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": port}},
		"outbounds": []any{withBase(out, serverPort)},
		"route":     map[string]any{"final": "out"},
	}
	raw, _ := json.Marshal(cfg)
	r := New(t.TempDir())
	if err := r.Apply(context.Background(), spec.Daemon{}, raw); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return fmt.Sprintf("127.0.0.1:%d", port)
}

// withBase adds the fields every client outbound shares.
func withBase(out map[string]any, port int) map[string]any {
	m := map[string]any{"tag": "out", "server": "127.0.0.1", "server_port": port}
	for k, v := range out {
		m[k] = v
	}
	return m
}

// roundTrip sends a line through the proxy to the echo server and reads it back.
func roundTrip(socks, target string) (net.Conn, error) {
	d, err := proxy.SOCKS5("tcp", socks, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	c, err := d.Dial("tcp", target)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("ping\n")); err != nil {
		c.Close()
		return nil, err
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

func daemonWith(protocol string, port int, sec spec.Security, users ...spec.User) spec.Daemon {
	return spec.Daemon{
		Kind: "singbox",
		Inbounds: []spec.Inbound{{
			Tag: "v", Protocol: protocol, Listen: "127.0.0.1", Port: port,
			Transport: spec.Transport{Type: spec.TransportTCP}, Security: sec, Users: users,
		}},
		Outbounds: []spec.Outbound{{Tag: "direct", Kind: spec.OutDirect}},
		Final:     "direct",
	}
}

// hotCase describes one protocol the live update test runs against.
type hotCase struct {
	protocol string
	user     func(n int64) spec.User
	outbound func(u spec.User) map[string]any
	security spec.Security
	tls      bool
}

var plainCases = []hotCase{
	{
		protocol: spec.ProtoVLESS, security: spec.Security{Type: spec.SecurityNone},
		user:     func(n int64) spec.User { return spec.User{ID: n, Name: fmt.Sprintf("u%d", n), UUID: uuid.NewString()} },
		outbound: func(u spec.User) map[string]any { return map[string]any{"type": "vless", "uuid": u.UUID} },
	},
	{
		protocol: spec.ProtoTrojan, security: spec.Security{Type: spec.SecurityNone},
		user: func(n int64) spec.User {
			return spec.User{ID: n, Name: fmt.Sprintf("u%d", n), Password: uuid.NewString()}
		},
		outbound: func(u spec.User) map[string]any { return map[string]any{"type": "trojan", "password": u.Password} },
	},
}

func TestUsersChangeWithoutRestartingTheInstance(t *testing.T) {
	for _, c := range plainCases {
		t.Run(c.protocol, func(t *testing.T) { runHotCase(t, c) })
	}
}

// runHotCase adds and removes users on a running inbound and checks nothing restarts and connections behave.
func runHotCase(t *testing.T, c hotCase) {
	target := echo(t)
	port := freePort(t)
	u1, u2 := c.user(1), c.user(2)

	r := New(t.TempDir())
	t.Cleanup(func() { r.Close() })
	apply := func(d spec.Daemon) {
		t.Helper()
		rendered, err := core.Get("singbox").Render(d)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Apply(context.Background(), d, rendered); err != nil {
			t.Fatal(err)
		}
	}

	apply(daemonWith(c.protocol, port, c.security, u1))
	box := r.instance

	long, err := roundTrip(client(t, port, c.outbound(u1)), target)
	if err != nil {
		t.Fatalf("the first user should connect: %v", err)
	}
	defer long.Close()

	// a second user arrives
	socksB := client(t, port, c.outbound(u2))
	if conn, err := roundTrip(socksB, target); err == nil {
		conn.Close()
		t.Fatal("a user nobody added must not get in")
	}
	apply(daemonWith(c.protocol, port, c.security, u1, u2))
	if r.instance != box {
		t.Fatal("adding a user restarted sing-box")
	}
	conn, err := roundTrip(socksB, target)
	if err != nil {
		t.Fatalf("the new user should connect without a restart: %v", err)
	}
	conn.Close()

	// the first user's open connection survived all of that
	_ = long.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := long.Write([]byte("more\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(long, buf); err != nil {
		t.Fatalf("an existing connection was dropped by adding someone else: %v", err)
	}

	// the first user is removed: new connections fail and the open one is cut
	apply(daemonWith(c.protocol, port, c.security, u2))
	if r.instance != box {
		t.Fatal("removing a user restarted sing-box")
	}
	if conn, err := roundTrip(client(t, port, c.outbound(u1)), target); err == nil {
		conn.Close()
		t.Fatal("a removed user must not connect")
	}
	_ = long.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = long.Write([]byte("again\n"))
	if _, err := io.ReadFull(long, buf); err == nil {
		t.Fatal("the removed user's open connection should have been cut")
	}
}

func TestVMessStillRestartsToChangeUsers(t *testing.T) {
	target := echo(t)
	port := freePort(t)
	mk := func(n int64) spec.User { return spec.User{ID: n, Name: fmt.Sprintf("u%d", n), UUID: uuid.NewString()} }
	u1, u2 := mk(1), mk(2)

	r := New(t.TempDir())
	t.Cleanup(func() { r.Close() })
	apply := func(d spec.Daemon) {
		rendered, err := core.Get("singbox").Render(d)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Apply(context.Background(), d, rendered); err != nil {
			t.Fatal(err)
		}
	}
	sec := spec.Security{Type: spec.SecurityNone}
	apply(daemonWith(spec.ProtoVMess, port, sec, u1))
	box := r.instance
	apply(daemonWith(spec.ProtoVMess, port, sec, u1, u2))
	if r.instance == box {
		t.Fatal("vmess is expected to restart, the hot path must leave it alone")
	}
	conn, err := roundTrip(client(t, port, map[string]any{"type": "vmess", "uuid": u2.UUID, "security": "auto"}), target)
	if err != nil {
		t.Fatalf("the new user should connect after the restart: %v", err)
	}
	conn.Close()
}
