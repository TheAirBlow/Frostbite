package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"frostbite/internal/db"
	"frostbite/internal/share"
	"frostbite/internal/spec"
)

// registerBridges registers the bridge wizard and the topology view.
func (s *Server) registerBridges(mux authMux) {
	mux.Admin("POST /bridges", s.createBridge)
	mux.Admin("GET /topology", s.topology)
}

// bridgeRequest is the JSON body for the bridge wizard.
type bridgeRequest struct {
	Kind            string         `json:"kind"` // relay or chain
	Name            string         `json:"name"`
	BridgeDaemonID  int64          `json:"bridge_daemon_id"`
	Port            int32          `json:"port"`
	TargetInboundID *int64         `json:"target_inbound_id"` // one of our own inbounds
	Link            string         `json:"link"`              // or any share link, chain only
	Upstream        *spec.Upstream `json:"upstream"`          // or a hand written upstream, chain only
	Preset          string         `json:"preset"`            // chain only: what the bridge itself accepts
	Params          map[string]any `json:"params"`
	Everyone        bool           `json:"everyone"` // chain only: send all of the bridge's traffic through the chain
}

// createBridge builds a relay or a chain in one go.
func (s *Server) createBridge(w http.ResponseWriter, r *http.Request) {
	var req bridgeRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	var (
		result any
		err    error
	)
	switch req.Kind {
	case "relay":
		result, err = s.buildRelay(r.Context(), req)
	case "chain":
		result, err = s.buildChain(r.Context(), req)
	default:
		badRequest(w, `kind must be "relay" or "chain"`)
		return
	}
	if err != nil {
		var be badBridge
		if _, _, named := spec.FieldOf(err); named {
			badInput(w, err)
			return
		}
		if asBad(err, &be) {
			badRequest(w, be.Error())
			return
		}
		dbError(w, err)
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "bridge."+req.Kind, req.Name, nil)
	created(w, result)
}

// badBridge is a mistake in the wizard input, as opposed to a server failure.
type badBridge string

func (e badBridge) Error() string { return string(e) }

// asBad unwraps a badBridge.
func asBad(err error, target *badBridge) bool {
	b, ok := err.(badBridge)
	if ok {
		*target = b
	}
	return ok
}

// buildRelay puts a dumb forwarder on the bridge node and advertises it as a host of the target.
func (s *Server) buildRelay(ctx context.Context, req bridgeRequest) (any, error) {
	if req.TargetInboundID == nil {
		return nil, spec.Invalid("target_inbound_id", "pick the inbound the relay should forward to")
	}
	if req.Port < 1 || req.Port > 65535 {
		return nil, spec.Invalid("port", "pick a port between 1 and 65535 for the relay")
	}
	target, err := s.Queries.GetInbound(ctx, *req.TargetInboundID)
	if err != nil {
		return nil, spec.Invalid("target_inbound_id", "the target inbound does not exist")
	}
	bridge, err := s.Queries.GetDaemon(ctx, req.BridgeDaemonID)
	if err != nil {
		return nil, spec.Invalid("bridge_daemon_id", "the bridge daemon does not exist")
	}
	bridgeNode, err := s.Queries.GetNode(ctx, bridge.NodeID)
	if err != nil {
		return nil, err
	}
	targetAddr, err := s.addressOf(ctx, target)
	if err != nil {
		return nil, err
	}

	tag, err := s.freeTag(ctx, bridge.ID, "relay-"+target.Tag, int(req.Port))
	if err != nil {
		return nil, err
	}
	fwd := inboundRequest{
		DaemonID: bridge.ID, Tag: tag, Remark: "relay to " + target.Tag, Protocol: spec.ProtoForward, Port: req.Port,
		Forward:  &spec.Forward{Address: targetAddr, Port: int(target.Port), Network: networkOf(target)},
		Security: spec.Security{Type: spec.SecurityNone},
	}
	if verr, err := s.check(ctx, fwd, 0); err != nil {
		return nil, err
	} else if verr != nil {
		return nil, verr
	}
	in, err := s.insertInbound(ctx, fwd)
	if err != nil {
		return nil, err
	}

	port := req.Port
	remark := "{node} {protocol} via " + bridgeNode.Name
	if n := strings.TrimSpace(req.Name); n != "" {
		remark = n
	}
	host, err := s.Queries.CreateHost(ctx, db.CreateHostParams{
		InboundID: target.ID, BridgeInboundID: &in.ID, Remark: remark, Address: bridgeNode.Address, Port: &port,
		Alpn: []string{}, Enabled: true,
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"inbound": in, "host": host}, nil
}

// networkOf says whether an inbound speaks tcp, udp or both, which is what a relay has to forward.
func networkOf(in db.Inbound) string {
	si := spec.Inbound{Protocol: in.Protocol, Transport: in.Transport}
	switch {
	case si.Network() == "udp":
		return "udp"
	case in.Protocol == spec.ProtoShadowsocks:
		return "tcp,udp"
	}
	return "tcp"
}

// addressOf is the address of the node an inbound lives on.
func (s *Server) addressOf(ctx context.Context, in db.Inbound) (string, error) {
	d, err := s.Queries.GetDaemon(ctx, in.DaemonID)
	if err != nil {
		return "", err
	}
	n, err := s.Queries.GetNode(ctx, d.NodeID)
	if err != nil {
		return "", err
	}
	return n.Address, nil
}

// buildChain makes the bridge a real server whose traffic leaves through another server.
func (s *Server) buildChain(ctx context.Context, req bridgeRequest) (any, error) {
	if req.Preset == "" {
		return nil, spec.Invalid("preset", "pick what the bridge itself should accept")
	}
	bridge, err := s.Queries.GetDaemon(ctx, req.BridgeDaemonID)
	if err != nil {
		return nil, spec.Invalid("bridge_daemon_id", "the bridge daemon does not exist")
	}

	out := outboundRequest{DaemonID: bridge.ID, Kind: spec.OutProxy, TargetInboundID: req.TargetInboundID, Upstream: req.Upstream, Link: req.Link}
	out.Tag = "chain-" + slug(req.Name, "exit")
	if req.TargetInboundID == nil && req.Link == "" && req.Upstream == nil {
		return nil, spec.Invalid("target_inbound_id", "pick where the chain should exit: one of your inbounds, a share link or a custom upstream")
	}

	// The outbound goes through the same checks as one made by hand.
	probe := httpRequestStub(ctx)
	if err := s.cleanOutbound(probe, &out); err != nil {
		return nil, badBridge(err.Error())
	}

	entry := inboundRequest{DaemonID: bridge.ID, Preset: req.Preset, Params: req.Params, Port: req.Port}
	if err := s.applyPreset(ctx, &entry); err != nil {
		return nil, badBridge(err.Error())
	}
	if verr, err := s.check(ctx, entry, 0); err != nil {
		return nil, err
	} else if verr != nil {
		return nil, badBridge(verr.Error())
	}

	ob, err := s.Queries.CreateOutbound(ctx, db.CreateOutboundParams{
		DaemonID: bridge.ID, Tag: out.Tag, Kind: spec.OutProxy, Upstream: out.Upstream, TargetInboundID: out.TargetInboundID,
	})
	if err != nil {
		return nil, err
	}
	in, err := s.insertInbound(ctx, entry)
	if err != nil {
		return nil, err
	}
	hosts := s.defaultHosts(ctx, in)

	rule, err := s.Queries.CreateRule(ctx, db.CreateRuleParams{
		DaemonID: &bridge.ID, Name: "chain " + in.Tag, Match: spec.Rule{InboundTags: []string{in.Tag}}, Outbound: ob.Tag, Enabled: true,
	})
	if err != nil {
		return nil, err
	}
	if req.Everyone {
		if _, err := s.Queries.UpdateDaemon(ctx, db.UpdateDaemonParams{
			ID: bridge.ID, Name: bridge.Name, Enabled: bridge.Enabled, LogLevel: bridge.LogLevel, DnsServers: bridge.DnsServers,
			DnsStrategy: bridge.DnsStrategy, FinalOutbound: ob.Tag, RawPatch: bridge.RawPatch,
			EdgeListen: bridge.EdgeListen, EdgeDefault: bridge.EdgeDefault,
		}); err != nil {
			return nil, err
		}
	}
	return map[string]any{"inbound": in, "outbound": ob, "rule": rule, "hosts": hosts}, nil
}

// slug turns a name into something safe for a tag.
func slug(name, def string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteRune(c)
		case c == ' ', c == '-', c == '_':
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return def
	}
	return b.String()
}

// httpRequestStub carries a context into helpers that expect a request.
func httpRequestStub(ctx context.Context) *http.Request {
	r, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	return r
}

// syncBridges keeps every relay pointing at the current address and port of its target, and every relay host at the relay.
func (s *Server) syncBridges(ctx context.Context) error {
	hosts, err := s.Queries.ListHosts(ctx)
	if err != nil {
		return err
	}
	for _, h := range hosts {
		if h.BridgeInboundID == nil {
			continue
		}
		fwd, err := s.Queries.GetInbound(ctx, *h.BridgeInboundID)
		if err != nil {
			continue
		}
		target, err := s.Queries.GetInbound(ctx, h.InboundID)
		if err != nil {
			continue
		}
		addr, err := s.addressOf(ctx, target)
		if err != nil {
			continue
		}

		want := &spec.Forward{Address: addr, Port: int(target.Port), Network: networkOf(target)}
		if fwd.Forward == nil || *fwd.Forward != *want {
			_, err := s.Queries.UpdateInbound(ctx, db.UpdateInboundParams{
				ID: fwd.ID, Tag: fwd.Tag, Remark: fwd.Remark, Protocol: fwd.Protocol, Listen: fwd.Listen, Port: fwd.Port,
				Transport: fwd.Transport, Security: fwd.Security, Options: fwd.Options, Sniffing: fwd.Sniffing,
				Forward: want, RawPatch: fwd.RawPatch, Enabled: fwd.Enabled, Sort: fwd.Sort,
				EdgeDaemonID: fwd.EdgeDaemonID, EdgeSni: fwd.EdgeSni,
			})
			if err != nil {
				return fmt.Errorf("relay %s: %w", fwd.Tag, err)
			}
		}

		bridgeAddr, err := s.addressOf(ctx, fwd)
		if err != nil {
			continue
		}
		port := fwd.Port
		if h.Address != bridgeAddr || h.Port == nil || *h.Port != port {
			_, err := s.Queries.UpdateHost(ctx, db.UpdateHostParams{
				ID: h.ID, Remark: h.Remark, Address: bridgeAddr, Port: &port, Sni: h.Sni, Host: h.Host, Path: h.Path, Alpn: h.Alpn,
				Fingerprint: h.Fingerprint, Insecure: h.Insecure, Mux: h.Mux, Fragment: h.Fragment, Enabled: h.Enabled, Sort: h.Sort,
			})
			if err != nil {
				return fmt.Errorf("relay host %d: %w", h.ID, err)
			}
		}
	}
	return nil
}

// removeBridgesTo deletes the relay forwarders that point at an inbound that is about to go away.
func (s *Server) removeBridgesTo(ctx context.Context, inboundID int64) error {
	hosts, err := s.Queries.ListHosts(ctx)
	if err != nil {
		return err
	}
	for _, h := range hosts {
		if h.InboundID == inboundID && h.BridgeInboundID != nil {
			if _, err := s.Queries.DeleteInbound(ctx, *h.BridgeInboundID); err != nil {
				return err
			}
		}
	}
	return nil
}

// topologyNode is a node as drawn on the topology view.
type topologyNode struct {
	ID      int64            `json:"id"`
	Name    string           `json:"name"`
	Address string           `json:"address"`
	Country string           `json:"country"`
	Daemons []topologyDaemon `json:"daemons"`
}

// topologyDaemon is a daemon with the inbounds that matter for drawing.
type topologyDaemon struct {
	ID       int64             `json:"id"`
	Kind     string            `json:"kind"`
	Name     string            `json:"name"`
	Online   bool              `json:"online"`
	Inbounds []topologyInbound `json:"inbounds"`
}

// topologyInbound is the short form of an inbound.
type topologyInbound struct {
	ID       int64  `json:"id"`
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
	Port     int32  `json:"port"`
	Relay    bool   `json:"relay"`
}

// topologyEdge is a link between two places.
type topologyEdge struct {
	Kind      string `json:"kind"` // relay, chain or custom
	FromNode  int64  `json:"from_node"`
	ToNode    int64  `json:"to_node,omitempty"`
	FromIn    int64  `json:"from_inbound,omitempty"`
	ToIn      int64  `json:"to_inbound,omitempty"`
	Label     string `json:"label"`
	CustomURL string `json:"custom,omitempty"` // where a chain to something we don't manage exits
}

// topology describes how nodes, relays and chains hang together.
func (s *Server) topology(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	nodes, err := s.Queries.ListNodes(ctx)
	if err != nil {
		internalError(w, err)
		return
	}
	daemons, err := s.Queries.ListDaemons(ctx)
	if err != nil {
		internalError(w, err)
		return
	}
	inbounds, err := s.Queries.ListInbounds(ctx)
	if err != nil {
		internalError(w, err)
		return
	}
	hosts, err := s.Queries.ListHosts(ctx)
	if err != nil {
		internalError(w, err)
		return
	}
	outbounds, err := s.Queries.ListOutbounds(ctx)
	if err != nil {
		internalError(w, err)
		return
	}

	nodeOf := map[int64]int64{} // daemon -> node
	inboundByID := map[int64]db.Inbound{}
	relays := map[int64]bool{}
	for _, d := range daemons {
		nodeOf[d.ID] = d.NodeID
	}
	for _, in := range inbounds {
		inboundByID[in.ID] = in
	}
	for _, h := range hosts {
		if h.BridgeInboundID != nil {
			relays[*h.BridgeInboundID] = true
		}
	}

	byNode := map[int64]*topologyNode{}
	outNodes := make([]*topologyNode, 0, len(nodes))
	for _, n := range nodes {
		tn := &topologyNode{ID: n.ID, Name: n.Name, Address: n.Address, Country: n.Country, Daemons: []topologyDaemon{}}
		byNode[n.ID] = tn
		outNodes = append(outNodes, tn)
	}
	daemonIdx := map[int64]*topologyDaemon{}
	for _, d := range daemons {
		tn := byNode[d.NodeID]
		if tn == nil {
			continue
		}
		tn.Daemons = append(tn.Daemons, topologyDaemon{ID: d.ID, Kind: d.Kind, Name: d.Name, Online: s.Hub.Status(d.ID).Online, Inbounds: []topologyInbound{}})
		daemonIdx[d.ID] = &tn.Daemons[len(tn.Daemons)-1]
	}
	for _, in := range inbounds {
		if td := daemonIdx[in.DaemonID]; td != nil {
			td.Inbounds = append(td.Inbounds, topologyInbound{ID: in.ID, Tag: in.Tag, Protocol: in.Protocol, Port: in.Port, Relay: relays[in.ID]})
		}
	}

	edges := []topologyEdge{}
	for _, h := range hosts {
		if h.BridgeInboundID == nil {
			continue
		}
		fwd, target := inboundByID[*h.BridgeInboundID], inboundByID[h.InboundID]
		edges = append(edges, topologyEdge{
			Kind: "relay", FromNode: nodeOf[fwd.DaemonID], ToNode: nodeOf[target.DaemonID], FromIn: fwd.ID, ToIn: target.ID,
			Label: fmt.Sprintf(":%d → %s", fwd.Port, target.Tag),
		})
	}
	for _, o := range outbounds {
		if o.Kind != spec.OutProxy {
			continue
		}
		e := topologyEdge{Kind: "chain", FromNode: nodeOf[o.DaemonID], Label: o.Tag}
		switch {
		case o.TargetInboundID != nil:
			t := inboundByID[*o.TargetInboundID]
			e.ToNode, e.ToIn = nodeOf[t.DaemonID], t.ID
		case o.Upstream != nil:
			e.Kind, e.CustomURL = "custom", fmt.Sprintf("%s:%d", o.Upstream.Address, o.Upstream.Port)
		default:
			continue
		}
		edges = append(edges, e)
	}
	ok(w, map[string]any{"nodes": outNodes, "edges": edges})
}

// parseUpstreamLink is used by the tools endpoint to preview a pasted link.
func parseUpstreamLink(link string) (spec.Upstream, error) { return share.ParseLink(link) }
