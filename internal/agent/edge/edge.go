// Package edge is a small TLS router: it reads the hello of each connection and hands it to the inbound that owns the server name.
package edge

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"frostbite/internal/agent/logs"
	"frostbite/internal/link"
	"frostbite/internal/spec"
)

// helloTimeout is how long a client may take to send its hello.
const helloTimeout = 10 * time.Second

// dialTimeout is how long reaching a target may take.
const dialTimeout = 10 * time.Second

// Runtime is the edge daemon.
type Runtime struct {
	table atomic.Pointer[table]
	logs  *logs.Ring

	mu        sync.Mutex
	listeners map[string]net.Listener
	conns     atomic.Int64
}

// table is a routing table, replaced as a whole.
type table struct {
	routes []spec.EdgeRoute
	def    string
}

// New creates a runtime.
func New() *Runtime {
	r := &Runtime{logs: logs.NewRing(1000), listeners: map[string]net.Listener{}}
	r.table.Store(&table{})
	return r
}

// Kind is the core this runtime drives.
func (r *Runtime) Kind() string { return "edge" }

// CoreVersion identifies the router.
func (r *Runtime) CoreVersion() string { return "frostbite-edge 1" }

// Apply swaps in the new table and starts or stops listeners to match. Connections already open are left alone.
func (r *Runtime) Apply(_ context.Context, d spec.Daemon, _ []byte) error {
	if d.Edge == nil {
		return errors.New("the spec has no edge section")
	}
	r.table.Store(&table{routes: d.Edge.Routes, def: d.Edge.Default})

	r.mu.Lock()
	defer r.mu.Unlock()

	want := map[string]bool{}
	for _, l := range d.Edge.Listen {
		want[l] = true
	}
	for addr, ln := range r.listeners {
		if !want[addr] {
			_ = ln.Close()
			delete(r.listeners, addr)
			r.logf("stopped listening on %s", addr)
		}
	}

	var failed []string
	for addr := range want {
		if _, ok := r.listeners[addr]; ok {
			continue
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", addr, err))
			continue
		}
		r.listeners[addr] = ln
		r.logf("listening on %s", addr)
		go r.accept(ln)
	}
	if len(failed) > 0 {
		return fmt.Errorf("could not listen on %s", strings.Join(failed, "; "))
	}
	return nil
}

// logf writes to the ring and the process log.
func (r *Runtime) logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	slog.Info("edge: " + msg)
	fmt.Fprintf(r.logs, "%s %s\n", time.Now().Format("15:04:05"), msg)
}

// accept hands each connection to a goroutine until the listener closes.
func (r *Runtime) accept(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				r.logf("accept failed: %v", err)
			}
			return
		}
		go r.handle(c)
	}
}

// handle routes one connection.
func (r *Runtime) handle(c net.Conn) {
	defer c.Close()
	r.conns.Add(1)
	defer r.conns.Add(-1)

	_ = c.SetReadDeadline(time.Now().Add(helloTimeout))
	hello, head, err := peekHello(c)
	_ = c.SetReadDeadline(time.Time{})

	t := r.table.Load()
	target, proxy := t.def, false
	if err == nil {
		if rt := t.match(hello.ServerName, hello.SupportedProtos); rt != nil {
			target, proxy = rt.Target, rt.Proxy
		}
	}
	if target == "" {
		return
	}

	up, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		r.logf("could not reach %s: %v", target, err)
		return
	}
	defer up.Close()

	if proxy {
		if _, err := up.Write(proxyHeader(c.RemoteAddr(), c.LocalAddr())); err != nil {
			return
		}
	}
	if _, err := up.Write(head); err != nil {
		return
	}
	pipe(c, up)
}

// match finds the first route for a server name and the protocols offered.
func (t *table) match(sni string, alpn []string) *spec.EdgeRoute {
	sni = strings.ToLower(strings.TrimSuffix(sni, "."))
	for i := range t.routes {
		rt := &t.routes[i]
		if !matchName(rt.SNI, sni) {
			continue
		}
		if len(rt.ALPN) > 0 && !overlaps(rt.ALPN, alpn) {
			continue
		}
		return rt
	}
	return nil
}

// matchName checks a name against exact and wildcard patterns.
func matchName(patterns []string, name string) bool {
	if name == "" {
		return false
	}
	for _, p := range patterns {
		p = strings.ToLower(p)
		if p == name {
			return true
		}
		if rest, ok := strings.CutPrefix(p, "*."); ok && strings.HasSuffix(name, "."+rest) {
			return true
		}
	}
	return false
}

// overlaps reports whether the two lists share an entry.
func overlaps(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// pipe copies both ways until either side is done.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

// recorder remembers everything read from a connection and refuses writes, so the TLS stack can look but not answer.
type recorder struct {
	net.Conn
	buf bytes.Buffer
}

func (r *recorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	r.buf.Write(p[:n])
	return n, err
}

func (r *recorder) Write([]byte) (int, error) {
	return 0, errors.New("the edge never answers a hello itself")
}

// errSeen stops the handshake as soon as the hello was parsed.
var errSeen = errors.New("hello seen")

// peekHello parses the client hello and returns it with the exact bytes read, for replaying to the target.
func peekHello(c net.Conn) (*tls.ClientHelloInfo, []byte, error) {
	rec := &recorder{Conn: c}
	var info *tls.ClientHelloInfo
	_ = tls.Server(rec, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			cp := *h
			cp.Conn = nil
			info = &cp
			return nil, errSeen
		},
	}).Handshake()
	if info == nil {
		return nil, rec.buf.Bytes(), errors.New("not a tls hello")
	}
	return info, rec.buf.Bytes(), nil
}

// proxyHeader builds a PROXY protocol v2 header for a tcp connection.
func proxyHeader(src, dst net.Addr) []byte {
	sa, ok1 := src.(*net.TCPAddr)
	da, ok2 := dst.(*net.TCPAddr)
	sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	if !ok1 || !ok2 {
		return append(sig, 0x20, 0x00, 0x00, 0x00) // LOCAL: no address info
	}

	s4, d4 := sa.IP.To4(), da.IP.To4()
	var b bytes.Buffer
	b.Write(sig)
	b.WriteByte(0x21)
	if s4 != nil && d4 != nil {
		b.WriteByte(0x11)
		b.Write([]byte{0x00, 0x0C})
		b.Write(s4)
		b.Write(d4)
	} else {
		b.WriteByte(0x21)
		b.Write([]byte{0x00, 0x24})
		b.Write(sa.IP.To16())
		b.Write(da.IP.To16())
	}
	b.Write([]byte{byte(sa.Port >> 8), byte(sa.Port), byte(da.Port >> 8), byte(da.Port)})
	return b.Bytes()
}

// Stats reports nothing per user, the edge does not know them.
func (r *Runtime) Stats(context.Context) (link.Stats, error) { return link.Stats{}, nil }

// Restart reopens every listener.
func (r *Runtime) Restart(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for addr, ln := range r.listeners {
		_ = ln.Close()
		delete(r.listeners, addr)
		nl, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		r.listeners[addr] = nl
		go r.accept(nl)
	}
	return nil
}

// Close stops every listener.
func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for addr, ln := range r.listeners {
		_ = ln.Close()
		delete(r.listeners, addr)
	}
	return nil
}

// Logs returns the tail of the edge's log.
func (r *Runtime) Logs(lines int) string { return r.logs.Tail(lines) }
