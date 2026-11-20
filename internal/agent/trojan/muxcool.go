package trojan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
)

// muxCoolHost is the destination Xray connects to when it multiplexes a trojan connection with Mux.Cool.
const muxCoolHost = "v1.mux.cool"

// Mux.Cool frames, see https://xtls.github.io/development/protocols/muxcool.html.
const (
	coolNew       = 0x01
	coolKeep      = 0x02
	coolEnd       = 0x03
	coolKeepAlive = 0x04

	coolOptData  = 0x01
	coolOptError = 0x02

	coolTCP = 0x01
	coolUDP = 0x02

	coolChunk = 8 << 10 // the largest payload Xray itself puts in a frame
)

// coolMux is one Mux.Cool connection, carrying any number of streams.
type coolMux struct {
	s    *server
	m    meta
	st   *state
	conn net.Conn
	wmu  sync.Mutex

	mu      sync.Mutex
	streams map[uint16]*coolStream
	wg      sync.WaitGroup
}

// coolStream is one connection inside the mux.
type coolStream struct {
	id   uint16
	udp  bool
	xudp bool // packets name their own address, as XUDP does
	dst  addr
	in   chan coolData
	done chan struct{}
	once sync.Once
	end  sync.Once
}

// coolData is the payload of a frame and, for XUDP, where it goes.
type coolData struct {
	b   []byte
	dst *addr
}

func (st *coolStream) close() { st.once.Do(func() { close(st.done) }) }

// deliver hands a payload to the stream, waiting while it is busy so a slow destination slows the client down.
func (st *coolStream) deliver(d coolData) {
	select {
	case st.in <- d:
	case <-st.done:
	}
}

// serveMuxCool reads frames until the client goes away.
func (s *server) serveMuxCool(ctx context.Context, m meta, conn net.Conn, st *state) {
	x := &coolMux{s: s, m: m, st: st, conn: conn, streams: map[uint16]*coolStream{}}
	ctx, cancel := context.WithCancel(ctx)
	if err := x.read(ctx); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		s.rt.logf(levelDebug, "%s: mux.cool: %v", m.user, err)
	}
	cancel()
	x.mu.Lock()
	for _, st := range x.streams {
		st.close()
	}
	x.mu.Unlock()
	_ = conn.Close()
	x.wg.Wait()
}

func (x *coolMux) read(ctx context.Context) error {
	var head [2]byte
	for {
		if _, err := io.ReadFull(x.conn, head[:]); err != nil {
			return err
		}
		size := binary.BigEndian.Uint16(head[:])
		if size < 4 || size > 512 {
			return fmt.Errorf("frame metadata of %d bytes", size)
		}
		meta := make([]byte, size)
		if _, err := io.ReadFull(x.conn, meta); err != nil {
			return err
		}
		id, status, opt := binary.BigEndian.Uint16(meta), meta[2], meta[3]
		var data []byte
		if opt&coolOptData != 0 {
			if _, err := io.ReadFull(x.conn, head[:]); err != nil {
				return err
			}
			data = make([]byte, binary.BigEndian.Uint16(head[:]))
			if _, err := io.ReadFull(x.conn, data); err != nil {
				return err
			}
		}

		switch status {
		case coolNew:
			network, dst, global, err := coolTarget(meta[4:])
			if err != nil {
				return err
			}
			st := &coolStream{id: id, udp: network == coolUDP, xudp: network == coolUDP && global, dst: dst,
				in: make(chan coolData, 16), done: make(chan struct{})}
			x.mu.Lock()
			if old := x.streams[id]; old != nil {
				old.close()
			}
			x.streams[id] = st
			x.mu.Unlock()
			x.wg.Add(1)
			go x.run(ctx, st, data)
		case coolKeep:
			st := x.stream(id)
			if st == nil {
				// a stream that ended here: tell the client so it stops sending
				if data != nil {
					_ = x.write(id, coolEnd, 0, nil, nil)
				}
				continue
			}
			var dst *addr
			if len(meta) > 4 && meta[4] == coolUDP {
				_, a, _, err := coolTarget(meta[4:])
				if err != nil {
					return err
				}
				dst = &a
			}
			if data != nil {
				st.deliver(coolData{b: data, dst: dst})
			}
		case coolEnd:
			if st := x.stream(id); st != nil {
				// the client ended it, so it needs no End back
				st.end.Do(func() {})
				st.close()
			}
		case coolKeepAlive:
		default:
			return fmt.Errorf("unknown frame status %d", status)
		}
	}
}

func (x *coolMux) stream(id uint16) *coolStream {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.streams[id]
}

// run carries one stream to its destination and tells the client when it ends.
func (x *coolMux) run(ctx context.Context, st *coolStream, first []byte) {
	defer x.wg.Done()
	defer func() {
		x.mu.Lock()
		if x.streams[st.id] == st {
			delete(x.streams, st.id)
		}
		x.mu.Unlock()
	}()
	var err error
	if st.udp {
		pc := &coolPackets{x: x, st: st, pending: first, has: first != nil}
		x.s.relayUDP(ctx, x.m, pc, st.close, udpTimeout(x.st))
	} else {
		c := &coolConn{x: x, st: st, pending: first}
		var head []byte
		if x.st.ib.Sniff != nil {
			head = first
		}
		err = x.s.tunnel(ctx, x.m, c, st.dst, head, x.st.ib.Sniff, nil)
	}
	st.close()
	st.end.Do(func() {
		var opt byte
		if err != nil {
			opt = coolOptError
		}
		_ = x.write(st.id, coolEnd, opt, nil, nil)
	})
}

// write sends one frame. extra goes into the metadata after the option byte.
func (x *coolMux) write(id uint16, status, opt byte, extra, data []byte) error {
	b := make([]byte, 0, 2+4+len(extra)+2+len(data))
	b = binary.BigEndian.AppendUint16(b, uint16(4+len(extra)))
	b = binary.BigEndian.AppendUint16(b, id)
	b = append(b, status, opt)
	b = append(b, extra...)
	if opt&coolOptData != 0 {
		b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
		b = append(b, data...)
	}
	x.wmu.Lock()
	defer x.wmu.Unlock()
	_, err := x.conn.Write(b)
	return err
}

// coolTarget reads NETWORK PORT ATYP ADDR, and whether an XUDP global id follows.
func coolTarget(b []byte) (network byte, a addr, global bool, err error) {
	if len(b) < 4 {
		return 0, addr{}, false, errors.New("short frame target")
	}
	network = b[0]
	if network != coolTCP && network != coolUDP {
		return 0, addr{}, false, fmt.Errorf("unknown network %d", network)
	}
	a.port = binary.BigEndian.Uint16(b[1:3])
	rest := b[4:]
	switch b[3] {
	case 0x01:
		if len(rest) < 4 {
			return 0, addr{}, false, errors.New("short frame target")
		}
		a.ip, rest = netip.AddrFrom4([4]byte(rest[:4])), rest[4:]
	case 0x03:
		if len(rest) < 16 {
			return 0, addr{}, false, errors.New("short frame target")
		}
		a.ip, rest = netip.AddrFrom16([16]byte(rest[:16])).Unmap(), rest[16:]
	case 0x02:
		if len(rest) < 1 || len(rest) < 1+int(rest[0]) || rest[0] == 0 {
			return 0, addr{}, false, errors.New("short frame target")
		}
		a.host, rest = string(rest[1:1+int(rest[0])]), rest[1+int(rest[0]):]
		if ip, perr := netip.ParseAddr(a.host); perr == nil {
			a.host, a.ip = "", ip.Unmap()
		}
	default:
		return 0, addr{}, false, fmt.Errorf("unknown address type %d", b[3])
	}
	var zero [8]byte
	global = len(rest) >= 8 && [8]byte(rest[:8]) != zero
	return network, a, global, nil
}

// appendCoolTarget writes NETWORK PORT ATYP ADDR for a UDP source.
func appendCoolTarget(b []byte, a addr) []byte {
	b = append(b, coolUDP)
	b = binary.BigEndian.AppendUint16(b, a.port)
	switch {
	case a.host != "":
		b = append(b, 0x02, byte(len(a.host)))
		b = append(b, a.host...)
	case a.ip.Is4():
		ip := a.ip.As4()
		b = append(b, 0x01)
		b = append(b, ip[:]...)
	default:
		ip := a.ip.As16()
		b = append(b, 0x03)
		b = append(b, ip[:]...)
	}
	return b
}

// coolConn is a TCP stream of the mux.
type coolConn struct {
	x       *coolMux
	st      *coolStream
	pending []byte
}

func (c *coolConn) Read(p []byte) (int, error) {
	for len(c.pending) == 0 {
		select {
		case d := <-c.st.in:
			c.pending = d.b
		case <-c.st.done:
			// End closes a stream for good, so the destination must not wait for more
			return 0, net.ErrClosed
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *coolConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		chunk := p[:min(len(p), coolChunk)]
		if err := c.x.write(c.st.id, coolKeep, coolOptData, nil, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func (c *coolConn) Close() error {
	c.st.close()
	return nil
}

// coolPackets is a UDP stream of the mux, one packet per frame.
type coolPackets struct {
	x       *coolMux
	st      *coolStream
	pending []byte
	has     bool
}

func (p *coolPackets) readPacket(b []byte) (int, addr, error) {
	if p.has {
		p.has = false
		return copy(b, p.pending), p.st.dst, nil
	}
	select {
	case d := <-p.st.in:
		dst := p.st.dst
		if d.dst != nil {
			dst = *d.dst
		}
		return copy(b, d.b), dst, nil
	case <-p.st.done:
		return 0, addr{}, io.EOF
	}
}

func (p *coolPackets) writePacket(b []byte, from addr) error {
	var extra []byte
	if p.st.xudp {
		extra = appendCoolTarget(nil, from)
	}
	return p.x.write(p.st.id, coolKeep, coolOptData, extra, b)
}
