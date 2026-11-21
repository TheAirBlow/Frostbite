package trojan

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// packetConn is a way UDP packets of a user arrive and return: trojan's own framing or a multiplexed stream.
type packetConn interface {
	readPacket(buf []byte) (n int, dst addr, err error)
	writePacket(b []byte, from addr) error
}

// relayUDP hands the packets of a user to the egress, routed by where the first one goes, until either side stops or
// nothing passes for timeout. conn, when there is one, carries the packets and takes their deadlines.
func (s *server) relayUDP(ctx context.Context, m meta, pc packetConn, closeClient func(), timeout time.Duration, conn net.Conn) {
	p := &packets{pc: pc, close: closeClient, conn: conn, scratch: make([]byte, maxPacket)}
	n, dst, err := pc.readPacket(p.scratch)
	if err != nil {
		return
	}
	p.first, p.firstDst = append([]byte(nil), p.scratch[:n]...), dst
	if err := s.rt.egress.RoutePackets(ctx, p, s.route(m, dst, timeout)); err != nil {
		s.rt.logf(levelDebug, "%s: udp to %s: %v", m.user, dst, err)
	}
}

// packets is a packetConn as sing's PacketConn. The first packet was read already, to learn where the flow goes.
type packets struct {
	pc       packetConn
	close    func()
	conn     net.Conn
	first    []byte
	firstDst addr
	sent     bool
	scratch  []byte // for packets larger than the buffer sing-box reads into
}

func (p *packets) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if !p.sent {
		p.sent = true
		_, err := buffer.Write(p.first)
		dst := p.firstDst
		p.first = nil
		return dst.socks(), err
	}
	free := buffer.FreeBytes()
	if len(free) >= maxPacket {
		n, dst, err := p.pc.readPacket(free)
		buffer.Truncate(buffer.Len() + n)
		return dst.socks(), err
	}
	if p.scratch == nil {
		p.scratch = make([]byte, maxPacket)
	}
	n, dst, err := p.pc.readPacket(p.scratch)
	if err != nil {
		return M.Socksaddr{}, err
	}
	_, err = buffer.Write(p.scratch[:n])
	return dst.socks(), err
}

func (p *packets) WritePacket(buffer *buf.Buffer, from M.Socksaddr) error {
	defer buffer.Release()
	return p.pc.writePacket(buffer.Bytes(), socksAddr(from))
}

func (p *packets) Close() error {
	p.close()
	return nil
}

func (p *packets) LocalAddr() net.Addr {
	if p.conn != nil {
		return p.conn.LocalAddr()
	}
	return &net.UDPAddr{}
}

func (p *packets) SetDeadline(t time.Time) error {
	if p.conn != nil {
		return p.conn.SetDeadline(t)
	}
	return nil
}

func (p *packets) SetReadDeadline(t time.Time) error {
	if p.conn != nil {
		return p.conn.SetReadDeadline(t)
	}
	return nil
}

func (p *packets) SetWriteDeadline(t time.Time) error {
	if p.conn != nil {
		return p.conn.SetWriteDeadline(t)
	}
	return nil
}

var _ N.PacketConn = (*packets)(nil)
