package trojan

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pires/go-proxyproto"

	"frostbite/internal/agent/egress"
	coretrojan "frostbite/internal/core/trojan"
)

const (
	dialTimeout      = 10 * time.Second
	handshakeTimeout = 15 * time.Second
	// requestTimeout is how long a visitor may wait after the handshake before saying anything, about what nginx allows.
	requestTimeout = 60 * time.Second
	idleTimeout    = 10 * time.Minute
)

// server is one listening inbound.
type server struct {
	rt     *Runtime
	tag    string
	addr   string
	socket socket
	ln     net.Listener
	state  atomic.Pointer[state]
	users  atomic.Pointer[map[string]string] // password hash -> user name

	connMu sync.Mutex
	conns  map[net.Conn]struct{}
}

// socket is everything about a listener that only a new socket can change.
type socket struct {
	listen              string
	proxy               bool
	reusePort, fastOpen bool
	keepAlive           bool
}

func socketOf(ib coretrojan.Inbound) socket {
	return socket{listen: ib.Listen, proxy: ib.AcceptProxy, reusePort: ib.TCP.ReusePort, fastOpen: ib.TCP.FastOpen, keepAlive: ib.TCP.KeepAlive}
}

// state is what the next connection to an inbound gets, swapped whole when the config or certificate changes.
type state struct {
	ib  coretrojan.Inbound
	tls *tls.Config
}

func newState(ib coretrojan.Inbound) (*state, error) {
	cfg, err := serverTLS(ib.TLS)
	if err != nil {
		return nil, err
	}
	if _, _, err := net.SplitHostPort(ib.Site.Dest); err != nil {
		return nil, errors.New("the site address must look like host:port")
	}
	return &state{ib: ib, tls: cfg}, nil
}

// listen opens the socket of an inbound and starts serving it.
func (r *Runtime) listen(ib coretrojan.Inbound, st *state, users map[string]string) (*server, error) {
	sock := socketOf(ib)
	lc := net.ListenConfig{Control: listenControl(sock.reusePort, sock.fastOpen)}
	if !sock.keepAlive {
		lc.KeepAlive = -1
	}
	ln, err := lc.Listen(context.Background(), "tcp", ib.Listen)
	if err != nil {
		return nil, err
	}
	if sock.proxy {
		// only the edge on this machine may say where a connection came from
		ln = &proxyproto.Listener{Listener: ln, ReadHeaderTimeout: 10 * time.Second, ConnPolicy: func(o proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			if a, ok := o.Upstream.(*net.TCPAddr); ok && a.IP.IsLoopback() {
				return proxyproto.USE, nil
			}
			return proxyproto.IGNORE, nil
		}}
	}
	if users == nil {
		users = map[string]string{}
	}
	s := &server{rt: r, tag: ib.Tag, addr: ib.Listen, socket: sock, ln: ln, conns: map[net.Conn]struct{}{}}
	s.state.Store(st)
	s.users.Store(&users)
	go s.serve()
	return s, nil
}

// serve hands connections to goroutines until the listener closes.
func (s *server) serve() {
	var backoff time.Duration
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// running out of file descriptors passes, so wait instead of giving up the port
			backoff = min(max(backoff*2, 5*time.Millisecond), time.Second)
			s.rt.logf(levelWarning, "accept on %s failed: %v", s.addr, err)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		go s.handle(c)
	}
}

func (s *server) track(c net.Conn) {
	s.connMu.Lock()
	s.conns[c] = struct{}{}
	s.connMu.Unlock()
}

func (s *server) untrack(c net.Conn) {
	s.connMu.Lock()
	delete(s.conns, c)
	s.connMu.Unlock()
}

// dropAll closes every connection the inbound accepted, visitors of the site included.
func (s *server) dropAll() {
	s.connMu.Lock()
	all := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		all = append(all, c)
	}
	s.connMu.Unlock()
	for _, c := range all {
		_ = c.Close()
	}
}

// meta says whose connection a tunnel belongs to.
type meta struct {
	inbound, user string
	src           net.Addr
}

// route describes a tunnel to the egress. timeout limits how long a packet flow may stay idle.
func (s *server) route(m meta, dst addr, timeout time.Duration) egress.Meta {
	return egress.Meta{Inbound: m.inbound, InboundType: "trojan", User: m.user, Source: m.src, Destination: dst.socks(), UDPTimeout: timeout}
}

// handle runs one connection from its first byte to the end.
func (s *server) handle(c net.Conn) {
	s.track(c)
	defer s.untrack(c)
	defer c.Close()
	st := s.state.Load()
	if tc := tcpOf(c); tc != nil {
		_ = tc.SetNoDelay(st.ib.TCP.NoDelay)
	}

	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	raw := bufio.NewReader(c)
	first, err := raw.Peek(1)
	if err != nil {
		return
	}
	if first[0] != 0x16 {
		s.plain(&bufConn{Conn: c, r: raw}, raw, st)
		return
	}
	tc := tls.Server(&bufConn{Conn: c, r: raw}, st.tls)
	if err := tc.Handshake(); err != nil {
		s.rt.logf(levelDebug, "tls handshake from %s failed: %v", addrIP(c.RemoteAddr()), err)
		return
	}
	cs := tc.ConnectionState()

	_ = c.SetDeadline(time.Now().Add(requestTimeout))
	br := bufio.NewReaderSize(tc, 16<<10)
	users := *s.users.Load()
	req, err := readRequest(br, users)
	if err != nil {
		if br.Buffered() == 0 && !errors.Is(err, errBad) {
			return
		}
		_ = c.SetDeadline(time.Time{})
		s.site(visit{conn: tc, br: br, sni: cs.ServerName, alpn: cs.NegotiatedProtocol, src: c.RemoteAddr(), dst: c.LocalAddr()}, st)
		return
	}
	_ = c.SetDeadline(time.Time{})
	_, _ = br.Discard(req.size)

	name := users[req.hash]
	sess := &session{inbound: s.tag, user: name, hash: req.hash, ip: addrIP(c.RemoteAddr()), kick: func() { _ = c.Close() }}
	cnt, done := s.rt.open(sess)
	defer done()
	// the user may have been removed while the request was on its way
	if (*s.users.Load())[req.hash] != name {
		return
	}
	cc := &countedConn{Conn: tc, br: br, c: cnt}
	m := meta{inbound: s.tag, user: name, src: c.RemoteAddr()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	switch {
	case req.cmd == cmdUDP:
		s.relayUDP(ctx, m, &trojanPackets{r: cc, w: cc}, func() { _ = c.Close() }, udpTimeout(st), cc)
	case req.dst.host == singMuxHost:
		s.serveSingMux(ctx, m, cc, st)
	case req.dst.host == muxCoolHost:
		s.serveMuxCool(ctx, m, cc, st)
	default:
		_ = s.tunnel(ctx, m, cc, req.dst)
	}
}

// readRequest waits for a trojan request, or for enough to know there is none.
func readRequest(br *bufio.Reader, users map[string]string) (request, error) {
	known := func(h string) bool { _, ok := users[h]; return ok }
	if _, err := br.Peek(1); err != nil {
		return request{}, err
	}
	for {
		b, _ := br.Peek(br.Buffered())
		req, err := parseRequest(b, known)
		if !errors.Is(err, errShort) {
			return req, err
		}
		if br.Buffered() >= br.Size() {
			return request{}, errBad
		}
		if _, err := br.Peek(br.Buffered() + 1); err != nil {
			return request{}, err
		}
	}
}

func udpTimeout(st *state) time.Duration {
	return time.Duration(st.ib.UDPTimeout) * time.Second
}

// tcpOf digs the TCP socket out of an accepted connection.
func tcpOf(c net.Conn) *net.TCPConn {
	switch v := c.(type) {
	case *net.TCPConn:
		return v
	case *proxyproto.Conn:
		tc, _ := v.TCPConn()
		return tc
	}
	return nil
}

// tunnel hands a TCP stream of a user to the egress, which sniffs, routes and dials it.
func (s *server) tunnel(ctx context.Context, m meta, client net.Conn, dst addr) error {
	err := s.rt.egress.RouteConn(ctx, client, s.route(m, dst, 0))
	if err != nil {
		s.rt.logf(levelDebug, "%s: tcp to %s: %v", m.user, dst, err)
	}
	return err
}

type halfCloser interface{ CloseWrite() error }

var copyBufs = sync.Pool{New: func() any { b := make([]byte, 32<<10); return &b }}

// relay moves bytes both ways until both sides are done or nothing passed for idleTimeout.
func relay(a, b io.ReadWriteCloser) {
	closeBoth := func() { _ = a.Close(); _ = b.Close() }
	idle := time.AfterFunc(idleTimeout, closeBoth)
	defer idle.Stop()
	var wg sync.WaitGroup
	pump := func(dst, src io.ReadWriteCloser) {
		defer wg.Done()
		bp := copyBufs.Get().(*[]byte)
		defer copyBufs.Put(bp)
		buf := *bp
		for {
			n, err := src.Read(buf)
			if n > 0 {
				idle.Reset(idleTimeout)
				if _, werr := dst.Write(buf[:n]); werr != nil {
					closeBoth()
					return
				}
			}
			if err != nil {
				// a side that is done sending may still be listening
				if hc, ok := dst.(halfCloser); ok && errors.Is(err, io.EOF) && hc.CloseWrite() == nil {
					return
				}
				closeBoth()
				return
			}
		}
	}
	wg.Add(2)
	go pump(b, a)
	go pump(a, b)
	wg.Wait()
}

// bufConn is a connection whose first bytes were already read into r, a reader of the same connection. Once r is
// drained, reads go to the connection itself and the buffer is let go.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) {
	if c.r != nil && c.r.Buffered() == 0 {
		c.r = nil
	}
	if c.r != nil {
		return c.r.Read(p)
	}
	return c.Conn.Read(p)
}

func (c *bufConn) CloseWrite() error {
	if hc, ok := c.Conn.(halfCloser); ok {
		return hc.CloseWrite()
	}
	return errors.ErrUnsupported
}

// countedConn is the tunnel of a user, counting what passes. br holds what was read past the request, as in bufConn.
type countedConn struct {
	net.Conn
	br *bufio.Reader
	c  *counter
}

func (c *countedConn) Read(p []byte) (n int, err error) {
	if c.br != nil && c.br.Buffered() == 0 {
		c.br = nil
	}
	if c.br != nil {
		n, err = c.br.Read(p)
	} else {
		n, err = c.Conn.Read(p)
	}
	c.c.up.Add(int64(n))
	return n, err
}

func (c *countedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.c.down.Add(int64(n))
	return n, err
}

func (c *countedConn) CloseWrite() error {
	if hc, ok := c.Conn.(halfCloser); ok {
		return hc.CloseWrite()
	}
	return errors.ErrUnsupported
}
