package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"frostbite/internal/spec"
)

// Supervised is a runtime whose core is a separate process that can die on its own.
type Supervised interface {
	Alive() bool
	// SetHooks registers down, run after the core exits unexpectedly or fails to start, and starting, run right before
	// it starts. Both are called with the runtime's lock held and must not call back into it.
	SetHooks(down, starting func())
	// Halt stops the core until it is configured or restarted again.
	Halt()
}

// guards probes cloaked inbounds, restarts a core that stops answering and serves the ports of a dead one.
type guards struct {
	rt Runtime

	mu     sync.Mutex
	list   map[string]*guard
	tries  int  // recoveries since the core last answered: restarts by the guard and unexpected exits
	halted bool // the guard gave up and stopped the core
}

// guard is the state of one guarded inbound.
type guard struct {
	tag    string
	listen string // host:port the inbound binds
	proxy  bool   // the inbound expects a PROXY header in front of every connection
	cloak  spec.Cloak

	next     time.Time
	fails    int
	targetOK bool
	ln       net.Listener // set while the guard serves the port itself
}

func newGuards(rt Runtime) *guards {
	g := &guards{rt: rt, list: map[string]*guard{}}
	if s, ok := rt.(Supervised); ok {
		s.SetHooks(g.down, g.releaseAll)
	}
	return g
}

// Want replaces the guarded inbounds with those of d.
func (g *guards) Want(d spec.Daemon) {
	g.mu.Lock()
	defer g.mu.Unlock()
	next := map[string]*guard{}
	for _, in := range d.Inbounds {
		c, ok := in.CloakOf()
		if !ok {
			continue
		}
		host := in.Listen
		if host == "0.0.0.0" || host == "::" {
			host = ""
		}
		gd := &guard{tag: in.Tag, listen: net.JoinHostPort(host, strconv.Itoa(in.Port)), proxy: in.Options.AcceptProxy, cloak: c, targetOK: true}
		gd.next = time.Now().Add(time.Duration(c.Interval) * time.Second)
		if old, ok := g.list[in.Tag]; ok && old.ln != nil {
			old.ln.Close()
		}
		next[in.Tag] = gd
	}
	for tag, old := range g.list {
		if _, ok := next[tag]; !ok && old.ln != nil {
			old.ln.Close()
		}
	}
	g.list = next
	g.tries, g.halted = 0, false
}

// Pause gives every port back before the core is reconfigured.
func (g *guards) Pause() { g.releaseAll() }

// releaseAll closes every takeover listener. Connections already relayed stay open.
func (g *guards) releaseAll() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, gd := range g.list {
		if gd.ln != nil {
			gd.ln.Close()
			gd.ln = nil
			slog.Info("guard: handing the port back to the core", "inbound", gd.tag)
		}
	}
}

// down runs when the core exits on its own or fails to start.
func (g *guards) down() {
	g.mu.Lock()
	g.tries++
	g.mu.Unlock()
	g.takeoverAll()
}

// takeoverAll serves every guarded port that allows it while the core is down.
func (g *guards) takeoverAll() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, gd := range g.list {
		if gd.ln != nil || !gd.cloak.Takeover {
			continue
		}
		ln, err := net.Listen("tcp", gd.listen)
		if err != nil {
			slog.Warn("guard: could not take over the port", "inbound", gd.tag, "addr", gd.listen, "err", err)
			continue
		}
		gd.ln = ln
		slog.Warn("guard: the core is down, passing the port straight to the real site", "inbound", gd.tag, "target", gd.cloak.Target)
		go serveTakeover(ln, gd.cloak, gd.proxy)
	}
}

// Run probes every guard on its own interval until ctx ends.
func (g *guards) Run(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			g.releaseAll()
			return
		case <-tick.C:
		}
		g.round(ctx)
	}
}

// round probes the guards that are due and acts on the results.
func (g *guards) round(ctx context.Context) {
	sup, _ := g.rt.(Supervised)
	if sup != nil && !sup.Alive() {
		g.takeoverAll()
		g.maybeGiveUp(sup)
		return
	}
	if sup != nil {
		// the panel restarted a halted core, so the guard starts counting afresh
		g.mu.Lock()
		if g.halted {
			g.halted, g.tries = false, 0
		}
		g.mu.Unlock()
	}

	now := time.Now()
	g.mu.Lock()
	var due []*guard
	for _, gd := range g.list {
		if gd.ln == nil && !now.Before(gd.next) {
			gd.next = now.Add(time.Duration(gd.cloak.Interval) * time.Second)
			due = append(due, gd)
		}
	}
	g.mu.Unlock()

	restart := false
	for _, gd := range due {
		if restart || ctx.Err() != nil {
			break
		}
		timeout := time.Duration(gd.cloak.Timeout) * time.Second
		err := probeTLS(ctx, dialAddr(gd.listen), gd.cloak.SNI, timeout, proxyVer(gd.proxy))
		if err == nil {
			gd.fails = 0
			g.mu.Lock()
			g.tries = 0
			g.mu.Unlock()
			continue
		}
		terr := probeTLS(ctx, gd.cloak.Target, gd.cloak.SNI, timeout, gd.cloak.XVer)
		if terr != nil {
			if gd.targetOK {
				slog.Warn("guard: the real site is unreachable, so the core is not blamed", "inbound", gd.tag, "target", gd.cloak.Target, "err", terr)
			}
			gd.targetOK, gd.fails = false, 0
			continue
		}
		gd.targetOK = true
		gd.fails++
		slog.Warn("guard: the inbound did not answer like the real site", "inbound", gd.tag, "failures", gd.fails, "of", gd.cloak.Failures, "err", err)
		if gd.fails >= gd.cloak.Failures && gd.cloak.Restart {
			restart = true
		}
	}
	if !restart {
		return
	}

	if sup != nil && g.maybeGiveUp(sup) {
		return
	}
	slog.Error("guard: restarting the core")
	g.mu.Lock()
	g.tries++
	g.mu.Unlock()
	if err := g.rt.Restart(ctx); err != nil {
		slog.Error("guard: restart failed", "err", err)
	}
	g.mu.Lock()
	for _, gd := range g.list {
		gd.fails = 0
		gd.next = time.Now().Add(time.Duration(gd.cloak.Interval) * time.Second)
	}
	g.mu.Unlock()
}

// maybeGiveUp stops the core for good once recoveries keep failing, leaving every guarded port with the real site.
// Cores that run inside the agent cannot be stopped this way, they are only restarted.
func (g *guards) maybeGiveUp(sup Supervised) bool {
	g.mu.Lock()
	limit, takeover := 0, false
	for _, gd := range g.list {
		if gd.cloak.Takeover && (limit == 0 || gd.cloak.GiveUp < limit) {
			limit, takeover = gd.cloak.GiveUp, true
		}
	}
	give := takeover && !g.halted && g.tries >= limit
	if give {
		g.halted = true
	}
	tries := g.tries
	g.mu.Unlock()
	if !give {
		return false
	}
	slog.Error("guard: the core did not recover, stopping it and sending the traffic straight to the real site", "attempts", tries)
	sup.Halt()
	g.takeoverAll()
	return true
}

// proxyVer is the PROXY header version a probe sends, 2 when the inbound expects one.
func proxyVer(expect bool) int {
	if expect {
		return 2
	}
	return 0
}

// dialAddr turns a listen address into one that can be dialled locally.
func dialAddr(listen string) string {
	host, port, _ := net.SplitHostPort(listen)
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// probeTLS completes a TLS handshake with addr, optionally after a LOCAL PROXY header. The certificate is not checked:
// the point is that something answers like the real site.
func probeTLS(ctx context.Context, addr, sni string, timeout time.Duration, xver int) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	if xver > 0 {
		if _, err := raw.Write(proxyHeader(xver, nil, nil)); err != nil {
			return err
		}
	}
	c := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	return c.HandshakeContext(ctx)
}

// serveTakeover relays every connection on ln to the real site until ln closes.
func serveTakeover(ln net.Listener, c spec.Cloak, stripProxy bool) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				slog.Warn("guard: accept failed", "err", err)
			}
			return
		}
		go relayTakeover(conn, c, stripProxy)
	}
}

// relayTakeover passes one connection to the real site, carrying the client address along when the site expects it.
func relayTakeover(conn net.Conn, c spec.Cloak, stripProxy bool) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	src, dst := conn.RemoteAddr(), conn.LocalAddr()
	if stripProxy {
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		s, d, err := readProxyHeader(br)
		_ = conn.SetReadDeadline(time.Time{})
		if err != nil {
			return
		}
		if s != nil {
			src, dst = s, d
		}
	}

	up, err := net.DialTimeout("tcp", c.Target, time.Duration(c.Timeout)*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	if c.XVer > 0 {
		if _, err := up.Write(proxyHeader(c.XVer, src, dst)); err != nil {
			return
		}
	}

	done := make(chan struct{}, 2)
	cp := func(dst io.Writer, src io.Reader, closer net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := closer.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(up, br, up)
	go cp(conn, up, conn)
	<-done
	<-done
}
