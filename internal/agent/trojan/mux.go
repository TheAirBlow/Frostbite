package trojan

import (
	"bufio"
	"context"
	"net"
	"time"

	smux "github.com/sagernet/sing-mux"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// singMuxHost is the destination sing-box, mihomo and their kin connect to when they multiplex a trojan connection.
var singMuxHost = smux.Destination.Fqdn

// serveSingMux runs a sing-mux session over the tunnel of a user, each stream routed on its own.
func (s *server) serveSingMux(ctx context.Context, m meta, conn net.Conn, st *state) {
	svc, err := smux.NewService(smux.ServiceOptions{
		NewStreamContext: func(ctx context.Context, _ net.Conn) context.Context { return ctx },
		Logger:           logger.NOP(),
		HandlerEx:        &singMuxHandler{s: s, m: m, st: st},
		Padding:          st.ib.Padding,
	})
	if err != nil {
		s.rt.logf(levelError, "multiplexing: %v", err)
		return
	}
	svc.NewConnectionEx(ctx, conn, M.SocksaddrFromNet(conn.RemoteAddr()), smux.Destination, nil)
}

// singMuxHandler takes the streams of one session.
type singMuxHandler struct {
	s  *server
	m  meta
	st *state
}

func (h *singMuxHandler) NewConnectionEx(ctx context.Context, conn net.Conn, _, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var head []byte
	var client net.Conn = conn
	if h.st.ib.Sniff != nil {
		br := bufio.NewReader(conn)
		head = peekHead(conn, br)
		client = &bufConn{Conn: conn, r: br}
	}
	err := h.s.tunnel(ctx, h.m, client, socksAddr(destination), head, h.st.ib.Sniff, func() { _ = N.ReportHandshakeSuccess(conn) })
	if err != nil {
		_ = N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	_ = conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

func (h *singMuxHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = N.ReportHandshakeSuccess(conn)
	h.s.relayUDP(ctx, h.m, singPackets{conn}, func() { _ = conn.Close() }, udpTimeout(h.st))
	if onClose != nil {
		onClose(nil)
	}
}

// singPackets reads and writes packets of a sing-mux stream.
type singPackets struct{ c N.PacketConn }

func (p singPackets) readPacket(b []byte) (int, addr, error) {
	buffer := buf.With(b)
	dst, err := p.c.ReadPacket(buffer)
	if err != nil {
		return 0, addr{}, err
	}
	return copy(b, buffer.Bytes()), socksAddr(dst), nil
}

func (p singPackets) writePacket(b []byte, from addr) error {
	// the stream writes the address and length in front of the payload, in place
	front, rear := N.CalculateFrontHeadroom(p.c), N.CalculateRearHeadroom(p.c)
	buffer := buf.NewSize(front + len(b) + rear)
	buffer.Resize(front, 0)
	_, _ = buffer.Write(b)
	dst := M.ParseSocksaddrHostPort(from.host, from.port)
	if from.host == "" {
		dst = M.SocksaddrFrom(from.ip, from.port)
	}
	return p.c.WritePacket(buffer, dst)
}

// socksAddr turns a sing address into a destination.
func socksAddr(a M.Socksaddr) addr {
	if a.IsFqdn() {
		return addr{host: a.Fqdn, port: a.Port}
	}
	return addr{ip: a.Addr.Unmap(), port: a.Port}
}

// sniffWait is how long a tunnel waits for the client to speak first, so its server name can be read.
const sniffWait = 300 * time.Millisecond

// peekHead waits briefly for the first bytes a client sends through a tunnel, leaving them in br.
func peekHead(c net.Conn, br *bufio.Reader) []byte {
	if br.Buffered() == 0 && c.SetReadDeadline(time.Now().Add(sniffWait)) == nil {
		_, _ = br.Peek(1)
		_ = c.SetReadDeadline(time.Time{})
	}
	b, _ := br.Peek(br.Buffered())
	return b
}
