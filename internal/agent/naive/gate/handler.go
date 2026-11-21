// Package gate is the Caddy side of the Frostbite naive daemon. It authenticates proxy clients against a user table the
// agent keeps current, tunnels them through the egress, counts their traffic and can cut them off, and hands everything
// else on to the next handler, which serves the real site.
package gate

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"frostbite/internal/agent/egress"
)

func init() { caddy.RegisterModule(&Gate{}) }

// Gate tunnels authenticated proxy requests and passes every other request on.
type Gate struct {
	// Inbound names the user table this gate checks, and the inbound rules match tunnels by.
	Inbound string `json:"inbound"`
}

// CaddyModule returns the module information.
func (*Gate) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.frostbite_gate",
		New: func() caddy.Module { return new(Gate) },
	}
}

// Validate makes sure the gate knows what it guards.
func (g *Gate) Validate() error {
	if g.Inbound == "" {
		return fmt.Errorf("inbound is required")
	}
	return nil
}

// ServeHTTP tunnels users that authenticate and passes everyone else on untouched, as if no proxy were here.
func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// the site behind must never see proxy credentials, valid or not
	pass := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		r.Header.Del("Proxy-Authorization")
		return next.ServeHTTP(w, r)
	})

	name, password, ok := proxyCredentials(r)
	if !ok || !registry.check(g.Inbound, name, password) {
		return pass.ServeHTTP(w, r)
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	t := &tunnel{cancel: cancel, body: r.Body}
	if c, ok := r.Context().Value(caddyhttp.ConnCtxKey).(net.Conn); ok {
		t.conn = c
	}
	var done func()
	t.counter, done = registry.open(&session{inbound: g.Inbound, user: name, ip: clientIP(r), kick: t.kill})
	defer done()

	r = r.WithContext(ctx)
	r.Body = &countedBody{ReadCloser: r.Body, t: t}
	cw := &countedWriter{ResponseWriter: w, t: t}
	m := egress.Meta{Inbound: g.Inbound, InboundType: "naive", User: name, Source: remoteAddr(r)}
	if r.Method == http.MethodConnect {
		return serveConnect(cw, r, t, m)
	}
	if !r.URL.IsAbs() {
		// credentials sent to the site itself, which is no proxy request
		return pass.ServeHTTP(w, r)
	}
	return serveForward(cw, r, m)
}

// proxyCredentials reads the Basic credentials of a Proxy-Authorization header.
func proxyCredentials(r *http.Request) (name, password string, ok bool) {
	kind, token, found := strings.Cut(r.Header.Get("Proxy-Authorization"), " ")
	if !found || !strings.EqualFold(kind, "basic") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return "", "", false
	}
	name, password, ok = strings.Cut(string(raw), ":")
	return name, password, ok
}

// clientIP is the address the user connected from. Behind the edge it comes from the PROXY header.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// remoteAddr is the user's end of the connection, nil when Caddy names it in a way that does not parse.
func remoteAddr(r *http.Request) net.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return nil
	}
	return net.TCPAddrFromAddrPort(ap)
}

// tunnel cuts one proxied request off from both ends and counts what passes.
type tunnel struct {
	*counter
	cancel func()
	body   io.Closer
	killed atomic.Bool

	mu   sync.Mutex
	conn net.Conn // the client's connection, which carries this tunnel and nobody else's
}

// kill ends the tunnel. The proxy closes the target once it notices the client is gone.
func (t *tunnel) kill() {
	t.killed.Store(true)
	t.cancel()
	_ = t.body.Close()
	t.mu.Lock()
	conn := t.conn
	t.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

// end closes this tunnel alone. Over HTTP/2 the connection carries other tunnels, which go on.
func (t *tunnel) end() {
	t.cancel()
	_ = t.body.Close()
}

// localAddr is the server's end of the client's connection.
func (t *tunnel) localAddr() net.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn == nil {
		return nil
	}
	return t.conn.LocalAddr()
}

func (t *tunnel) setConn(c net.Conn) {
	t.mu.Lock()
	t.conn = c
	t.mu.Unlock()
}

// countedBody counts what the client uploads.
type countedBody struct {
	io.ReadCloser
	t *tunnel
}

func (b *countedBody) Read(p []byte) (int, error) {
	if b.t.killed.Load() {
		return 0, net.ErrClosed
	}
	n, err := b.ReadCloser.Read(p)
	b.t.up.Add(int64(n))
	return n, err
}

// countedWriter counts what the client downloads.
type countedWriter struct {
	http.ResponseWriter
	t *tunnel
}

func (w *countedWriter) Write(p []byte) (int, error) {
	if w.t.killed.Load() {
		return 0, net.ErrClosed
	}
	n, err := w.ResponseWriter.Write(p)
	w.t.down.Add(int64(n))
	return n, err
}

// Unwrap lets http.ResponseController reach Flush on the real writer.
func (w *countedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Hijack hands out a connection that counts too, for tunnels over HTTP/1.1.
func (w *countedWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	w.t.setConn(conn)
	// bytes the server already buffered are sent on by the proxy without passing through the connection
	w.t.up.Add(int64(rw.Reader.Buffered()))
	return &countedConn{Conn: conn, t: w.t}, rw, nil
}

// countedConn counts a hijacked connection.
type countedConn struct {
	net.Conn
	t *tunnel
}

func (c *countedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.t.up.Add(int64(n))
	return n, err
}

func (c *countedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.t.down.Add(int64(n))
	return n, err
}

// CloseWrite lets the proxy half close the client side, as it does on a plain connection.
func (c *countedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

var (
	_ caddy.Validator             = (*Gate)(nil)
	_ caddyhttp.MiddlewareHandler = (*Gate)(nil)
)
