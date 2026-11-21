// Package egress is the way out for the native daemons: sing-box running with no inbounds, which sniffs, routes,
// resolves and dials for them exactly as the sing-box daemon would. A daemon authenticates a client itself and hands
// each stream or packet flow over with the inbound and user it belongs to.
package egress

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

// ErrNotRunning is returned while no config has started.
var ErrNotRunning = errors.New("the egress is not running")

// Egress routes connections through a sing-box instance that is replaced whenever its config changes.
type Egress struct {
	sink    func(level, msg string)
	logPath string   // where sing-box writes its log, see New
	logPipe *os.File // the write end behind logPath, kept open for every instance to come

	mu    sync.Mutex
	raw   []byte             // the config asked for
	err   error              // why raw is not running yet, nil once it is
	retry context.CancelFunc // stops the retries of raw
	cur   atomic.Pointer[instance]
}

// Retries of a config that failed to start begin after firstRetry and back off to lastRetry.
var (
	firstRetry = 5 * time.Second
	lastRetry  = 5 * time.Minute
)

type instance struct {
	box    *box.Box
	cancel context.CancelFunc
}

// New creates an egress that passes sing-box's log lines to sink, with levels debug, info, warning or error.
func New(sink func(level, msg string)) *Egress {
	e := &Egress{sink: sink, logPath: "stderr"}
	// sing-box only logs to a path, and a pipe opened through /proc is one; elsewhere its lines go to stderr
	if r, w, err := os.Pipe(); err == nil && runtime.GOOS == "linux" {
		e.logPath, e.logPipe = fmt.Sprintf("/proc/self/fd/%d", w.Fd()), w
		go forward(r, sink)
	}
	return e
}

// forward reads log lines such as "WARN dns: ..." and hands them to sink.
func forward(r io.Reader, sink func(level, msg string)) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		word, msg, _ := strings.Cut(sc.Text(), " ")
		level := "error"
		switch word {
		case "TRACE", "DEBUG":
			level = "debug"
		case "INFO":
			level = "info"
		case "WARN":
			level = "warning"
		}
		sink(level, msg)
	}
}

// Apply runs raw, a sing-box config. The same config again changes nothing and returns why it is not running, if it
// is not. A new one starts before the old one stops, and connections that went through the old one are cut. A config
// that fails to start, say because a rule set can't be downloaded yet, is retried in the background while the one
// before it, if any, keeps routing.
func (e *Egress) Apply(raw []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.raw != nil && bytes.Equal(e.raw, raw) {
		return e.err
	}
	if e.retry != nil {
		e.retry()
		e.retry = nil
	}
	e.raw = bytes.Clone(raw)
	next, again, err := e.build(raw)
	if err != nil {
		e.err = err
		if again {
			ctx, cancel := context.WithCancel(context.Background())
			e.retry = cancel
			go e.retryStart(ctx, e.raw)
		}
		return err
	}
	e.err = nil
	if old := e.cur.Swap(next); old != nil {
		old.close()
	}
	return nil
}

// retryStart starts raw again and again until it runs or ctx ends.
func (e *Egress) retryStart(ctx context.Context, raw []byte) {
	delay := firstRetry
	for {
		e.sink("warning", fmt.Sprintf("retrying in %v: %v", delay, e.Err()))
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		next, _, err := e.build(raw)
		e.mu.Lock()
		if ctx.Err() != nil {
			e.mu.Unlock()
			if next != nil {
				next.close()
			}
			return
		}
		if err == nil {
			e.err, e.retry = nil, nil
			old := e.cur.Swap(next)
			e.mu.Unlock()
			if old != nil {
				old.close()
			}
			e.sink("info", "started after all")
			return
		}
		e.err = err
		e.mu.Unlock()
		delay = min(delay*2, lastRetry)
	}
}

// Err says why the config asked for is not running, nil when it is.
func (e *Egress) Err() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}

// build starts an instance of raw. again says whether trying later may go better.
func (e *Egress) build(raw []byte) (_ *instance, again bool, err error) {
	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	var opts option.Options
	if err := opts.UnmarshalJSONContext(ctx, raw); err != nil {
		cancel()
		return nil, false, fmt.Errorf("sing-box rejected the egress config: %w", err)
	}
	if opts.Log == nil {
		opts.Log = &option.LogOptions{}
	}
	opts.Log.Output, opts.Log.Timestamp, opts.Log.DisableColor = e.logPath, false, true
	b, err := box.New(box.Options{Options: opts, Context: ctx})
	if err != nil {
		cancel()
		return nil, false, fmt.Errorf("sing-box rejected the egress config: %w", err)
	}
	if err := b.Start(); err != nil {
		_ = b.Close()
		cancel()
		return nil, true, fmt.Errorf("the egress failed to start: %w", err)
	}
	return &instance{box: b, cancel: cancel}, false, nil
}

func (in *instance) close() {
	_ = in.box.Close()
	in.cancel()
}

// Close stops the egress for good.
func (e *Egress) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.retry != nil {
		e.retry()
		e.retry = nil
	}
	if old := e.cur.Swap(nil); old != nil {
		old.close()
	}
	e.raw, e.err = nil, nil
	return nil
}

// Meta says where a connection comes from and where it asks to go.
type Meta struct {
	Inbound     string // the tag rules match on
	InboundType string
	User        string
	Source      net.Addr
	Destination M.Socksaddr
	UDPTimeout  time.Duration // how long a packet flow may stay idle, sing-box's default when zero
}

func (m Meta) context() adapter.InboundContext {
	c := adapter.InboundContext{
		Inbound: m.Inbound, InboundType: m.InboundType, User: m.User,
		Destination: m.Destination, UDPTimeout: m.UDPTimeout,
	}
	if m.Source != nil {
		c.Source = M.SocksaddrFromNet(m.Source).Unwrap()
	}
	return c
}

// RouteConn carries conn to where the rules send m.Destination and returns once both directions are done. conn may
// implement the handshake interfaces of sing's network package to learn whether the destination answered. A stream to
// the UDP over TCP address carries packets, which are routed as a packet flow.
func (e *Egress) RouteConn(ctx context.Context, conn net.Conn, m Meta) error {
	switch m.Destination.Fqdn {
	case uot.MagicAddress:
		req, err := uot.ReadRequest(conn)
		if err != nil {
			return fmt.Errorf("udp over tcp request: %w", err)
		}
		m.Destination = req.Destination
		return e.RoutePackets(ctx, uot.NewConn(conn, *req), m)
	case uot.LegacyMagicAddress:
		m.Destination = M.Socksaddr{Addr: netip.IPv4Unspecified()}
		return e.RoutePackets(ctx, uot.NewConn(conn, uot.Request{}), m)
	}
	in := e.cur.Load()
	if in == nil {
		return ErrNotRunning
	}
	done := make(chan error, 1)
	var once sync.Once
	in.box.Router().RouteConnectionEx(ctx, conn, m.context(), func(err error) { once.Do(func() { done <- err }) })
	return <-done
}

// RoutePackets carries the packets of conn the same way, until either side stops or the flow goes idle. A flow that
// names no destination is routed by where its first packet goes.
func (e *Egress) RoutePackets(ctx context.Context, conn N.PacketConn, m Meta) error {
	in := e.cur.Load()
	if in == nil {
		return ErrNotRunning
	}
	if !m.Destination.IsFqdn() && (!m.Destination.Addr.IsValid() || m.Destination.Addr.IsUnspecified()) {
		first := buf.NewPacket()
		dst, err := conn.ReadPacket(first)
		if err != nil {
			first.Release()
			return err
		}
		m.Destination = dst
		conn = &replayPackets{PacketConn: conn, first: first, dst: dst}
	}
	done := make(chan error, 1)
	var once sync.Once
	in.box.Router().RoutePacketConnectionEx(ctx, conn, m.context(), func(err error) { once.Do(func() { done <- err }) })
	return <-done
}

// Dial opens a connection to m.Destination through the rules, for daemons that need a connection of their own rather
// than one to hand over. It returns once the destination answered or the dial failed.
func (e *Egress) Dial(ctx context.Context, m Meta) (net.Conn, error) {
	if e.cur.Load() == nil {
		return nil, ErrNotRunning
	}
	ours, theirs := net.Pipe()
	p := &dialPipe{Conn: theirs, result: make(chan error, 1)}
	go func() {
		err := e.RouteConn(context.WithoutCancel(ctx), p, m)
		p.report(err)
		_ = theirs.Close()
	}()
	select {
	case err := <-p.result:
		if err != nil {
			_ = ours.Close()
			return nil, err
		}
		return ours, nil
	case <-ctx.Done():
		_ = ours.Close()
		return nil, ctx.Err()
	}
}

// replayPackets hands out a packet that was read already before the rest.
type replayPackets struct {
	N.PacketConn
	first *buf.Buffer
	dst   M.Socksaddr
}

func (c *replayPackets) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	if c.first == nil {
		return c.PacketConn.ReadPacket(b)
	}
	_, err := b.Write(c.first.Bytes())
	c.first.Release()
	c.first = nil
	return c.dst, err
}

// dialPipe is the far end of a Dial, which learns from sing-box whether the destination answered.
type dialPipe struct {
	net.Conn
	once   sync.Once
	result chan error
}

func (p *dialPipe) report(err error) {
	if err == nil {
		err = net.ErrClosed
	}
	p.once.Do(func() { p.result <- err })
}

func (p *dialPipe) ConnHandshakeSuccess(net.Conn) error {
	p.once.Do(func() { p.result <- nil })
	return nil
}

func (p *dialPipe) HandshakeFailure(err error) error {
	p.report(err)
	return nil
}

// Config turns a rendered egress into the bytes Apply takes. A missing one routes everything direct.
func Config(raw json.RawMessage) []byte {
	if len(raw) == 0 || string(raw) == "null" {
		return []byte(`{"outbounds":[{"type":"direct","tag":"direct"}]}`)
	}
	return raw
}
