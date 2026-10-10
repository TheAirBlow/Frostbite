// Package mtproto is a Telegram proxy with one secret per user, so usage can be counted and cut off per person.
package mtproto

import (
	"context"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"frostbite/internal/agent/logs"
	"frostbite/internal/link"
	"frostbite/internal/spec"
)

const (
	handshakeTimeout = 15 * time.Second
	dialTimeout      = 10 * time.Second
	idleTimeout      = 10 * time.Minute
)

// dcAddrs are Telegram's data centers, reached directly.
var dcAddrs = map[int]string{
	1: "149.154.175.50:443",
	2: "149.154.167.51:443",
	3: "149.154.175.100:443",
	4: "149.154.167.91:443",
	5: "149.154.171.5:443",
}

// Runtime is the mtproto daemon.
type Runtime struct {
	logs *logs.Ring
	dcs  map[int]string // where each data center lives, replaceable for tests

	mu      sync.Mutex
	servers map[string]*server
	last    spec.Daemon

	usageMu sync.Mutex
	usage   map[string]*link.Usage

	liveMu sync.Mutex
	live   map[*session]struct{}
}

// server is one listening inbound.
type server struct {
	rt      *Runtime
	tag     string
	addr    string
	mode    string
	domain  string
	ln      net.Listener
	users   atomic.Pointer[[]user]
	replays replays
}

// user is one secret that may connect.
type user struct {
	label  string
	secret []byte
}

// session is one proxied connection.
type session struct {
	tag   string
	label string
	ip    string
	close func()
}

// New creates a runtime.
func New() *Runtime {
	return &Runtime{
		logs: logs.NewRing(1000), dcs: dcAddrs,
		servers: map[string]*server{}, usage: map[string]*link.Usage{}, live: map[*session]struct{}{},
	}
}

// Kind is the core this runtime drives.
func (r *Runtime) Kind() string { return "mtproto" }

// CoreVersion identifies the proxy.
func (r *Runtime) CoreVersion() string { return "frostbite-mtproto 1" }

func (r *Runtime) logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	slog.Info("mtproto: " + msg)
	fmt.Fprintf(r.logs, "%s %s\n", time.Now().Format("15:04:05"), msg)
}

// Apply starts, updates and stops listeners to match d. Users change without dropping anyone else.
func (r *Runtime) Apply(_ context.Context, d spec.Daemon, _ []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last = d

	want := map[string]bool{}
	var failed []error
	for _, in := range d.Inbounds {
		if in.Protocol != spec.ProtoMTProto {
			continue
		}
		want[in.Tag] = true
		users := usersOf(in)
		mode := in.Options.MTMode
		if mode == "" {
			mode = "faketls"
		}
		addr := net.JoinHostPort(in.Listen, strconv.Itoa(in.Port))

		if s, ok := r.servers[in.Tag]; ok && s.addr == addr && s.mode == mode && s.domain == in.Options.MTDomain {
			s.users.Store(&users)
			r.kick(in.Tag, users)
			continue
		}
		if s, ok := r.servers[in.Tag]; ok {
			s.stop()
			r.kick(in.Tag, nil)
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			failed = append(failed, fmt.Errorf("%s: %w", addr, err))
			delete(r.servers, in.Tag)
			continue
		}
		s := &server{rt: r, tag: in.Tag, addr: addr, mode: mode, domain: in.Options.MTDomain, ln: ln}
		s.users.Store(&users)
		r.servers[in.Tag] = s
		r.logf("listening on %s (%s)", addr, mode)
		go s.accept()
	}
	for tag, s := range r.servers {
		if !want[tag] {
			s.stop()
			delete(r.servers, tag)
			r.logf("stopped %s", s.addr)
		}
	}
	return errors.Join(failed...)
}

// usersOf decodes the secrets of an inbound's users.
func usersOf(in spec.Inbound) []user {
	out := make([]user, 0, len(in.Users))
	for _, u := range in.Users {
		b, err := hex.DecodeString(u.Password)
		if err != nil || len(b) != 16 {
			continue
		}
		out = append(out, user{label: u.Name, secret: b})
	}
	return out
}

// kick drops sessions of users that are gone.
func (r *Runtime) kick(tag string, users []user) {
	keep := map[string]bool{}
	for _, u := range users {
		keep[u.label] = true
	}
	r.liveMu.Lock()
	var drop []*session
	for s := range r.live {
		if s.tag == tag && !keep[s.label] {
			drop = append(drop, s)
		}
	}
	r.liveMu.Unlock()
	for _, s := range drop {
		s.close()
	}
}

func (s *server) stop() { _ = s.ln.Close() }

// accept hands connections to goroutines until the listener closes.
func (s *server) accept() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				s.rt.logf("accept on %s failed: %v", s.addr, err)
			}
			return
		}
		go s.handle(c)
	}
}

// handle runs one client from its first byte to the end.
func (s *server) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))

	var (
		client net.Conn = c
		secret []byte
		label  string
	)
	users := *s.users.Load()

	init := make([]byte, initLen)
	if s.mode == "faketls" {
		rec, err := readHello(c)
		if err != nil {
			s.front(c, rec)
			return
		}
		now := time.Now()
		var u *user
		for i := range users {
			if checkHello(users[i].secret, rec, now) {
				u = &users[i]
				break
			}
		}
		if u == nil || !s.replays.fresh(rec[11:43], now) {
			s.front(c, rec)
			return
		}
		flight, err := serverFlight(u.secret, rec)
		if err != nil {
			return
		}
		if _, err := c.Write(flight); err != nil {
			return
		}
		client = &recordConn{Conn: c}
		secret, label = u.secret, u.label
		if _, err := io.ReadFull(client, init); err != nil {
			return
		}
	} else if _, err := io.ReadFull(c, init); err != nil {
		return
	}

	var (
		dec, enc cipher.Stream
		tag      [4]byte
		dc       int
	)
	for _, u := range candidates(users, secret, label) {
		d, e, t, n, err := accept(init, u.secret)
		if err == nil {
			dec, enc, tag, dc, label = d, e, t, n, u.label
			break
		}
	}
	if dec == nil {
		return
	}

	if dc < 0 {
		dc = -dc
	}
	addr, ok := s.rt.dcs[dc]
	if !ok {
		addr = s.rt.dcs[2]
	}
	up, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		s.rt.logf("could not reach telegram dc %d: %v", dc, err)
		return
	}
	defer up.Close()
	hello, uenc, udec := dial(nil, tag, dc)
	if _, err := up.Write(hello); err != nil {
		return
	}

	_ = c.SetDeadline(time.Time{})
	from := &secretConn{Conn: client, dec: dec, enc: enc}
	to := &secretConn{Conn: up, dec: udec, enc: uenc}
	s.rt.relay(s.tag, label, c.RemoteAddr(), from, to, c, up)
}

// candidates are the secrets worth trying: just one once the hello has named the user.
func candidates(all []user, secret []byte, label string) []user {
	if secret != nil {
		return []user{{label: label, secret: secret}}
	}
	return all
}

// front passes a stranger on to the real site, so probing the port shows an ordinary web server.
func (s *server) front(c net.Conn, head []byte) {
	if s.domain == "" {
		return
	}
	up, err := net.DialTimeout("tcp", frontAddr(s.domain), dialTimeout)
	if err != nil {
		return
	}
	defer up.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := up.Write(head); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}

// relay moves bytes both ways, counting them for the user, until either side stops.
func (r *Runtime) relay(tag, label string, remote net.Addr, from, to io.ReadWriter, a, b net.Conn) {
	host, _, _ := net.SplitHostPort(remote.String())
	closeBoth := func() { _ = a.Close(); _ = b.Close() }
	sess := &session{tag: tag, label: label, ip: host, close: closeBoth}
	r.liveMu.Lock()
	r.live[sess] = struct{}{}
	r.liveMu.Unlock()
	defer func() {
		r.liveMu.Lock()
		delete(r.live, sess)
		r.liveMu.Unlock()
	}()

	var up, down atomic.Int64
	done := make(chan struct{}, 2)
	go func() { n, _ := copyIdle(to, from, a); up.Add(n); closeBoth(); done <- struct{}{} }()
	go func() { n, _ := copyIdle(from, to, b); down.Add(n); closeBoth(); done <- struct{}{} }()
	<-done
	<-done
	r.add(label, up.Load(), down.Load())
}

// copyIdle copies until an error, pushing the idle deadline forward on every read.
func copyIdle(dst io.Writer, src io.Reader, c net.Conn) (int64, error) {
	var total int64
	buf := make([]byte, 32*1024)
	for {
		_ = c.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := src.Read(buf)
		if n > 0 {
			w, werr := dst.Write(buf[:n])
			total += int64(w)
			if werr != nil {
				return total, werr
			}
		}
		if err != nil {
			return total, err
		}
	}
}

// add books traffic to a user.
func (r *Runtime) add(label string, up, down int64) {
	r.usageMu.Lock()
	defer r.usageMu.Unlock()
	u := r.usage[label]
	if u == nil {
		u = &link.Usage{}
		r.usage[label] = u
	}
	u.Up += up
	u.Down += down
}

// Stats returns usage since the last call and who is connected now.
func (r *Runtime) Stats(context.Context) (link.Stats, error) {
	r.usageMu.Lock()
	users := make(map[string]link.Usage, len(r.usage))
	for k, v := range r.usage {
		users[k] = *v
	}
	clear(r.usage)
	r.usageMu.Unlock()

	online := map[string][]string{}
	r.liveMu.Lock()
	for s := range r.live {
		if !contains(online[s.label], s.ip) {
			online[s.label] = append(online[s.label], s.ip)
		}
	}
	r.liveMu.Unlock()
	return link.Stats{Users: users, Online: online}, nil
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// Restart drops every connection and listens again.
func (r *Runtime) Restart(ctx context.Context) error {
	r.mu.Lock()
	for tag, s := range r.servers {
		s.stop()
		delete(r.servers, tag)
	}
	last := r.last
	r.mu.Unlock()
	r.dropAll()
	return r.Apply(ctx, last, nil)
}

func (r *Runtime) dropAll() {
	r.liveMu.Lock()
	var all []*session
	for s := range r.live {
		all = append(all, s)
	}
	r.liveMu.Unlock()
	for _, s := range all {
		s.close()
	}
}

// Logs returns the tail of the log.
func (r *Runtime) Logs(lines int) string { return r.logs.Tail(lines) }

// Close stops everything.
func (r *Runtime) Close() error {
	r.mu.Lock()
	for _, s := range r.servers {
		s.stop()
	}
	r.mu.Unlock()
	r.dropAll()
	return nil
}

// frontAddr is where strangers are sent: the cover site, on 443 unless a port is given.
func frontAddr(domain string) string {
	if _, _, err := net.SplitHostPort(domain); err == nil {
		return domain
	}
	return net.JoinHostPort(domain, "443")
}
