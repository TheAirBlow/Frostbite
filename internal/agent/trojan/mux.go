package trojan

import (
	"context"
	"net"

	smux "github.com/sagernet/sing-mux"
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
	// the stream reports to its client whether the destination answered
	err := h.s.rt.egress.RouteConn(ctx, conn, h.s.route(h.m, socksAddr(destination), 0))
	if onClose != nil {
		onClose(err)
	}
}

func (h *singMuxHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, _, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	err := h.s.rt.egress.RoutePackets(ctx, conn, h.s.route(h.m, socksAddr(destination), udpTimeout(h.st)))
	if onClose != nil {
		onClose(err)
	}
}

// socksAddr turns a sing address into a destination.
func socksAddr(a M.Socksaddr) addr {
	if a.IsFqdn() {
		return addr{host: a.Fqdn, port: a.Port}
	}
	return addr{ip: a.Addr.Unmap(), port: a.Port}
}
