package compose

import (
	"net"
	"slices"
	"strconv"

	"frostbite/internal/db"
	"frostbite/internal/share"
	"frostbite/internal/spec"
)

// Profile is one connection a user can import: an upstream plus where it came from.
type Profile struct {
	spec.Upstream
	NodeID    int64  `json:"node_id"`
	NodeName  string `json:"node_name"`
	InboundID int64  `json:"inbound_id"`
	HostID    int64  `json:"host_id"`
	Country   string `json:"country"`
	Bridge    bool   `json:"bridge"`
	// Via says the profile only works together with a Turnable app: "turnable" is the tunnel itself, "turnable-local"
	// a connection to the port the Turnable app listens on.
	Via string `json:"via,omitempty"`
}

// ProfileMode says which kind of app the profiles are for.
type ProfileMode int

const (
	// ModeAll lists everything, for pages a person reads.
	ModeAll ProfileMode = iota
	// ModeStandard is for ordinary VPN apps. Turnable tunnels are replaced by connections to the local port of the
	// Turnable app, for the destinations that offer one.
	ModeStandard
	// ModeTurnable is for Turnable apps, which only understand their own links.
	ModeTurnable
)

// Profiles lists every connection a user may use, given the squads they are in.
func (t *Topology) Profiles(u db.User, squadIDs []int64, mode ProfileMode) []Profile {
	allowed := map[int64]bool{}
	for _, sq := range squadIDs {
		for _, id := range t.SquadInbounds[sq] {
			allowed[id] = true
		}
	}

	var ids []int64
	for id := range allowed {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b int64) int {
		ia, ib := t.Inbounds[a], t.Inbounds[b]
		na, nb := t.Nodes[t.Daemons[ia.DaemonID].NodeID], t.Nodes[t.Daemons[ib.DaemonID].NodeID]
		switch {
		case na.Sort != nb.Sort:
			return int(na.Sort - nb.Sort)
		case na.ID != nb.ID:
			return int(na.ID - nb.ID)
		case ia.Sort != ib.Sort:
			return int(ia.Sort - ib.Sort)
		}
		return int(a - b)
	})

	var out []Profile
	for _, id := range ids {
		in, ok := t.Inbounds[id]
		if !ok || !in.Enabled || in.Protocol == spec.ProtoForward {
			continue
		}
		d := t.Daemons[in.DaemonID]
		node := t.Nodes[d.NodeID]
		if !d.Enabled || !node.Enabled {
			continue
		}

		isTurnable := in.Protocol == spec.ProtoTurnable
		if mode == ModeTurnable && !isTurnable {
			continue
		}
		si := t.specInbound(in)
		if si.IsLoopback() {
			continue
		}
		if isTurnable && mode != ModeTurnable {
			out = append(out, t.localProfiles(in, si, node, u, allowed)...)
		}
		if isTurnable && mode == ModeStandard {
			continue
		}
		user := UserFor(si, u)
		hosts := t.Hosts[id]
		if len(hosts) == 0 {
			hosts = []db.Host{{ID: 0, InboundID: id, Remark: "{node} {protocol}", Enabled: true}}
		}
		for _, h := range hosts {
			if !h.Enabled {
				continue
			}
			ep := share.Endpoint{Inbound: si, Host: HostOf(h), NodeAddress: node.Address, NodeName: node.Name, Country: node.Country}
			up, err := share.Upstream(ep, user)
			if err != nil {
				continue
			}
			if in.Protocol == spec.ProtoShadowTLS {
				inner, ok := t.detourOf(in, u, ep)
				if !ok {
					continue
				}
				up.Inner = &inner
			}
			p := Profile{
				Upstream: up, NodeID: node.ID, NodeName: node.Name, InboundID: id, HostID: h.ID, Country: node.Country,
				Bridge: h.BridgeInboundID != nil,
			}
			if isTurnable {
				p.Via = "turnable"
			}
			out = append(out, p)
		}
	}
	return out
}

// detourOf describes the inbound a shadowtls inbound forwards to, as the client sees it.
func (t *Topology) detourOf(in db.Inbound, u db.User, outer share.Endpoint) (spec.Upstream, bool) {
	for _, o := range t.Inbounds {
		if o.DaemonID != in.DaemonID || o.Tag != in.Options.STLSDetour {
			continue
		}
		si := specInbound(o)
		ep := share.Endpoint{Inbound: si, Host: outer.Host, NodeAddress: outer.NodeAddress, NodeName: outer.NodeName}
		ep.Host.Port, ep.Host.Path, ep.Host.Host = outer.Host.Port, "", ""
		inner, err := share.Upstream(ep, UserFor(si, u))
		if err != nil {
			return spec.Upstream{}, false
		}
		return inner, true
	}
	return spec.Upstream{}, false
}

// specInbound is specInbound with the destinations of a Turnable inbound resolved against the current topology.
func (t *Topology) specInbound(in db.Inbound) spec.Inbound {
	si := specInbound(in)
	if in.Protocol == spec.ProtoTurnable {
		si.Options = t.ResolveRoutes(si.Options)
	}
	return si
}

// LoopbackTarget is where something on the same node reaches an inbound.
func LoopbackTarget(in db.Inbound) string {
	host := in.Listen
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(int(in.Port)))
}

// ResolveRoutes points the Turnable destinations that lead to one of the panel's inbounds at that inbound's current
// address, so changing its port does not leave a tunnel dangling.
func (t *Topology) ResolveRoutes(o spec.Options) spec.Options {
	if len(o.TRoutes) == 0 {
		return o
	}
	routes := slices.Clone(o.TRoutes)
	for i, r := range routes {
		if r.Kind != spec.RouteInbound {
			continue
		}
		if target, ok := t.Inbounds[r.InboundID]; ok {
			routes[i].Target = LoopbackTarget(target)
		}
	}
	o.TRoutes = routes
	return o
}

// localProfiles are the connections ordinary apps get for the destinations of a Turnable inbound: ones that point at
// the port the Turnable app listens on, in whatever form the thing behind the tunnel needs.
func (t *Topology) localProfiles(in db.Inbound, si spec.Inbound, node db.Node, u db.User, allowed map[int64]bool) []Profile {
	var out []Profile
	for _, r := range si.Options.TurnableRoutes() {
		if !r.IsLocal() {
			continue
		}
		var (
			up spec.Upstream
			ok bool
		)
		switch r.Kind {
		case spec.RouteInbound:
			up, ok = t.localInbound(r, node, u, allowed)
		case spec.RouteCustom:
			up, ok = localCustom(r, si, node, u)
		}
		if ok {
			out = append(out, Profile{Upstream: up, NodeID: node.ID, NodeName: node.Name, InboundID: in.ID, Country: node.Country, Via: "turnable-local"})
		}
	}
	return out
}

// localInbound describes one of the panel's inbounds as seen through a Turnable tunnel: same credentials and
// settings, but the address is the port of the Turnable app on the device.
func (t *Topology) localInbound(r spec.TurnableRouteSpec, node db.Node, u db.User, allowed map[int64]bool) (spec.Upstream, bool) {
	target, ok := t.Inbounds[r.InboundID]
	// a user without access to the inbound has no credentials on it
	if !ok || !target.Enabled || !allowed[target.ID] || target.Protocol == spec.ProtoForward || target.Protocol == spec.ProtoTurnable || target.Protocol == spec.ProtoShadowTLS {
		return spec.Upstream{}, false
	}
	tsi := specInbound(target)
	host := hostFor(t.Hosts[target.ID])
	host.Address, host.Port = "127.0.0.1", r.LocalPort
	host.Remark = r.Name
	if host.Remark == "" {
		host.Remark = "{node} " + firstNonEmpty(target.Remark, target.Tag)
	}

	// The app talks to localhost, but the server still has to be addressed by its own name.
	name := firstNonEmpty(host.SNI, tsi.Security.SNI, acmeDomain(tsi.Security))
	if name == "" && net.ParseIP(node.Address) == nil {
		name = node.Address
	}
	if host.SNI == "" && tsi.Security.Type == spec.SecurityTLS {
		host.SNI = name
	}
	switch tsi.Transport.Type {
	case spec.TransportWS, spec.TransportHTTPUpgrade, spec.TransportXHTTP:
		if host.Host == "" && tsi.Transport.Host == "" {
			host.Host = name
		}
	}

	up, err := share.Upstream(share.Endpoint{Inbound: tsi, Host: host, NodeAddress: "127.0.0.1", NodeName: node.Name, Country: node.Country}, UserFor(tsi, u))
	return up, err == nil
}

// localCustom renders a link written by hand for a destination.
func localCustom(r spec.TurnableRouteSpec, si spec.Inbound, node db.Node, u db.User) (spec.Upstream, bool) {
	cred := UserFor(si, u)
	name := r.Name
	if name == "" {
		name = node.Name + " " + r.ID
	}
	link := spec.ExpandRouteURL(r.URL, map[string]string{
		"host": "127.0.0.1", "port": strconv.Itoa(r.LocalPort), "user": u.Username, "uuid": cred.UUID, "password": cred.Password,
		"name": name, "node": node.Name, "country": node.Country, "route": r.ID,
	})
	// A link the panel understands can be drawn in every format. Any other is handed over as it is.
	up, err := share.ParseLink(link)
	if err != nil {
		up = spec.Upstream{Protocol: "custom", Address: "127.0.0.1", Port: r.LocalPort}
	}
	up.RawLink, up.Name = link, name
	return up, true
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func acmeDomain(s spec.Security) string {
	if s.ACME != nil {
		return s.ACME.Domain
	}
	return ""
}
