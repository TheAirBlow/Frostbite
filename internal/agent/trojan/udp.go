package trojan

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"frostbite/internal/spec"
)

// packetConn is a way UDP packets of a user arrive and return: trojan's own framing or a multiplexed stream.
type packetConn interface {
	readPacket(buf []byte) (n int, dst addr, err error)
	writePacket(b []byte, from addr) error
}

// relayUDP carries the packets of a user between pc and the internet until either side stops or nothing passes for
// timeout. Packets keep their order per destination and go out through the outbound the rules pick.
func (s *server) relayUDP(ctx context.Context, m meta, pc packetConn, closeClient func(), timeout time.Duration) {
	rt := s.rt.router.Load()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	idle := time.AfterFunc(timeout, cancel)
	defer idle.Stop()

	var (
		mu    sync.Mutex
		socks = map[string]*net.UDPConn{}   // by outbound
		addrs = map[string]netip.AddrPort{} // where a named destination went, by outbound and name
		outs  = map[addr]outbound{}         // the route of each destination, only touched by the reading loop
		wg    sync.WaitGroup
	)
	go func() {
		<-ctx.Done()
		closeClient()
		mu.Lock()
		for _, c := range socks {
			_ = c.Close()
		}
		mu.Unlock()
	}()

	socket := func(out outbound) (*net.UDPConn, error) {
		mu.Lock()
		defer mu.Unlock()
		if c := socks[out.tag]; c != nil {
			return c, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		c, err := rt.listenUDP(out)
		if err != nil {
			return nil, err
		}
		socks[out.tag] = c
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, maxPacket)
			for {
				n, from, err := c.ReadFromUDPAddrPort(buf)
				if err != nil {
					return
				}
				idle.Reset(timeout)
				if err := pc.writePacket(buf[:n], addrOf(from)); err != nil {
					cancel()
					return
				}
			}
		}()
		return c, nil
	}

	resolve := func(out outbound, dst addr) (netip.AddrPort, error) {
		if dst.ip.IsValid() {
			return netip.AddrPortFrom(dst.ip, dst.port), nil
		}
		key := out.tag + "|" + dst.String()
		mu.Lock()
		ap, ok := addrs[key]
		mu.Unlock()
		if ok {
			return ap, nil
		}
		lctx, lcancel := context.WithTimeout(ctx, dialTimeout)
		defer lcancel()
		ips, err := rt.lookup(lctx, out, dst)
		if err != nil {
			return netip.AddrPort{}, err
		}
		ap = netip.AddrPortFrom(ips[0], dst.port)
		mu.Lock()
		addrs[key] = ap
		mu.Unlock()
		return ap, nil
	}

	buf := make([]byte, maxPacket)
	for {
		n, dst, err := pc.readPacket(buf)
		if err != nil {
			break
		}
		idle.Reset(timeout)
		out, ok := outs[dst]
		if !ok {
			out = rt.route(ctx, target{inbound: m.inbound, user: m.user, network: "udp", dst: dst})
			outs[dst] = out
		}
		if out.kind == spec.OutBlock {
			continue
		}
		ap, err := resolve(out, dst)
		if err != nil {
			s.rt.logf(levelDebug, "%s: udp to %s: %v", m.user, dst, err)
			continue
		}
		c, err := socket(out)
		if err != nil {
			s.rt.logf(levelWarning, "%s: no udp socket through %s: %v", m.user, out.tag, err)
			break
		}
		_, _ = c.WriteToUDPAddrPort(buf[:n], ap)
	}
	cancel()
	wg.Wait()
}
