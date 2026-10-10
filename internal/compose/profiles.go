package compose

import (
	"slices"

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
}

// Profiles lists every connection a user may use, given the squads they are in.
func (t *Topology) Profiles(u db.User, squadIDs []int64) []Profile {
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

		si := specInbound(in)
		if si.IsLoopback() {
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
			out = append(out, Profile{
				Upstream: up, NodeID: node.ID, NodeName: node.Name, InboundID: id, HostID: h.ID, Country: node.Country,
				Bridge: h.BridgeInboundID != nil,
			})
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
