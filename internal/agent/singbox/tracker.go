package singbox

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"

	"frostbite/internal/link"
)

// tracker counts bytes per user and remembers who is connected. sing-box calls it for every routed connection.
type tracker struct {
	mu     sync.Mutex
	counts map[string]*userCounter
	live   map[*liveConn]struct{}
	peers  atomic.Pointer[map[string]string] // tunnel address -> user label, for protocols that carry no user name
}

// setPeers replaces the address to user table.
func (t *tracker) setPeers(m map[string]string) { t.peers.Store(&m) }

// userOf names who a connection belongs to.
func (t *tracker) userOf(md adapter.InboundContext) string {
	if md.User != "" {
		return md.User
	}
	if p := t.peers.Load(); p != nil {
		return (*p)[md.Source.Addr.String()]
	}
	return ""
}

// userCounter holds one user's traffic since the last report, and their live connections by source address.
type userCounter struct {
	up, down atomic.Int64
	active   map[string]int
}

func newTracker() *tracker {
	return &tracker{counts: map[string]*userCounter{}, live: map[*liveConn]struct{}{}}
}

// liveConn is an open connection that can be cut.
type liveConn struct {
	user, inbound string
	closer        io.Closer
}

// track remembers an open connection until the returned function is called.
func (t *tracker) track(user, inbound string, c io.Closer) func() {
	lc := &liveConn{user: user, inbound: inbound, closer: c}
	t.mu.Lock()
	t.live[lc] = struct{}{}
	t.mu.Unlock()
	return func() {
		t.mu.Lock()
		delete(t.live, lc)
		t.mu.Unlock()
	}
}

// kick closes every open connection a user has through an inbound, after they lost access to it.
func (t *tracker) kick(user, inbound string) {
	t.mu.Lock()
	var victims []io.Closer
	for lc := range t.live {
		if lc.user == user && lc.inbound == inbound {
			victims = append(victims, lc.closer)
		}
	}
	t.mu.Unlock()
	for _, c := range victims {
		_ = c.Close()
	}
}

var _ adapter.ConnectionTracker = (*tracker)(nil)

// counter returns the entry for a user, creating it on first use.
func (t *tracker) counter(user string) *userCounter {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.counts[user]
	if c == nil {
		c = &userCounter{active: map[string]int{}}
		t.counts[user] = c
	}
	return c
}

// open notes a new connection from ip and returns what to call when it ends.
func (t *tracker) open(c *userCounter, ip string) func() {
	t.mu.Lock()
	c.active[ip]++
	t.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			if c.active[ip]--; c.active[ip] <= 0 {
				delete(c.active, ip)
			}
			t.mu.Unlock()
		})
	}
}

// RoutedConnection wraps a tcp style connection with counters.
func (t *tracker) RoutedConnection(_ context.Context, conn net.Conn, md adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	user := t.userOf(md)
	if user == "" {
		return conn
	}
	c := t.counter(user)
	release := t.open(c, md.Source.Addr.String())
	cc := &closeConn{Conn: bufio.NewInt64CounterConn(conn, []*atomic.Int64{&c.up}, []*atomic.Int64{&c.down})}
	untrack := t.track(user, md.Inbound, cc)
	cc.release = func() {
		release()
		untrack()
	}
	return cc
}

// RoutedPacketConnection wraps a udp style connection with counters.
func (t *tracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn, md adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	user := t.userOf(md)
	if user == "" {
		return conn
	}
	c := t.counter(user)
	release := t.open(c, md.Source.Addr.String())
	pc := &closePacketConn{PacketConn: bufio.NewInt64CounterPacketConn(conn, []*atomic.Int64{&c.up}, nil, []*atomic.Int64{&c.down}, nil)}
	untrack := t.track(user, md.Inbound, pc)
	pc.release = func() {
		release()
		untrack()
	}
	return pc
}

// RoutedFlow is only used by tun inbounds, which the panel never creates.
func (t *tracker) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}

// drain returns usage since the previous call and the addresses currently connected.
func (t *tracker) drain() link.Stats {
	t.mu.Lock()
	defer t.mu.Unlock()

	st := link.Stats{Users: map[string]link.Usage{}, Online: map[string][]string{}}
	for user, c := range t.counts {
		up, down := c.up.Swap(0), c.down.Swap(0)
		if up+down > 0 {
			st.Users[user] = link.Usage{Up: up, Down: down}
		}
		if len(c.active) > 0 {
			ips := make([]string, 0, len(c.active))
			for ip := range c.active {
				ips = append(ips, ip)
			}
			st.Online[user] = ips
		}
	}
	return st
}

// dropAll forgets live connections, since they all died with the instance. Counters stay so nothing unreported is lost.
func (t *tracker) dropAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, c := range t.counts {
		c.active = map[string]int{}
	}
}

// closeConn calls release when the connection closes.
type closeConn struct {
	net.Conn
	release func()
}

func (c *closeConn) Close() error {
	c.release()
	return c.Conn.Close()
}

func (c *closeConn) Upstream() any { return c.Conn }

// closePacketConn calls release when the packet connection closes.
type closePacketConn struct {
	N.PacketConn
	release func()
}

func (c *closePacketConn) Close() error {
	c.release()
	return c.PacketConn.Close()
}

func (c *closePacketConn) Upstream() any { return c.PacketConn }
