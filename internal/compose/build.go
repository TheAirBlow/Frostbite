package compose

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strconv"

	"frostbite/internal/db"
	"frostbite/internal/share"
	"frostbite/internal/spec"
	"frostbite/internal/warp"
)

// Build assembles the spec for one daemon.
func (s *Snapshot) Build(daemonID int64) (spec.Daemon, error) {
	d, ok := s.Daemons[daemonID]
	if !ok {
		return spec.Daemon{}, fmt.Errorf("daemon %d does not exist", daemonID)
	}

	if d.Kind == "edge" {
		return s.buildEdge(d)
	}

	out := spec.Daemon{
		Kind:     d.Kind,
		Log:      spec.Log{Level: d.LogLevel},
		DNS:      spec.DNS{Servers: d.DnsServers, Strategy: d.DnsStrategy},
		Final:    d.FinalOutbound,
		RawPatch: d.RawPatch,
	}

	systemUsers := s.chainTargets()
	for _, in := range s.byDaemon[daemonID] {
		if !in.Enabled {
			continue
		}
		out.Inbounds = append(out.Inbounds, s.inbound(in, systemUsers[in.ID]))
	}

	if err := s.portClash(d, out.Inbounds); err != nil {
		return spec.Daemon{}, err
	}

	outbounds, err := s.outbounds(d)
	if err != nil {
		return spec.Daemon{}, err
	}
	out.Outbounds = outbounds
	if !hasTag(out.Outbounds, out.Final) {
		out.Final = "direct"
	}
	out.Rules = s.rules(d, out.Outbounds)
	return out, nil
}

// inbound converts a stored inbound and attaches the users that may use it.
func (s *Snapshot) inbound(in db.Inbound, extra []spec.User) spec.Inbound {
	out := spec.Inbound{
		Tag: in.Tag, Protocol: in.Protocol, Listen: in.Listen, Port: int(in.Port),
		Transport: in.Transport, Security: in.Security, Options: in.Options, Sniffing: in.Sniffing,
		Forward: in.Forward, RawPatch: in.RawPatch,
	}
	if a := out.Security.ACME; a != nil && out.Security.Type == spec.SecurityTLS {
		out.Security.CertPath, out.Security.KeyPath = a.Paths(spec.ACMEDir)
	}
	if in.EdgeDaemonID != nil {
		// the edge owns the public port, so the inbound moves to a private one behind it
		out.Listen, out.Port = "127.0.0.1", InternalPort(in.ID)
		out.Options.AcceptProxy = s.Daemons[in.DaemonID].Kind == "xray"
	}
	if in.Protocol == spec.ProtoForward {
		return out
	}

	ids := s.usersOf(in)
	slices.Sort(ids)
	for _, id := range ids {
		out.Users = append(out.Users, UserFor(out, s.userByID[id]))
	}
	out.Users = append(out.Users, extra...)
	return out
}

// usersOf lists the users of an inbound, plus those of any shadowtls inbound that hands traffic to it.
func (s *Snapshot) usersOf(in db.Inbound) []int64 {
	ids := slices.Clone(s.inboundUsers[in.ID])
	for _, o := range s.byDaemon[in.DaemonID] {
		if o.Protocol == spec.ProtoShadowTLS && o.Options.STLSDetour == in.Tag {
			ids = append(ids, s.inboundUsers[o.ID]...)
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

// UserFor derives the credentials a user holds on one inbound.
func UserFor(in spec.Inbound, u db.User) spec.User {
	id, pass := spec.CredentialsFor(in.Protocol, in.Options.Method, u.Uuid, u.Password)
	return spec.User{ID: u.ID, Name: spec.UserName(u.ID), UUID: id, Password: pass, Flow: in.Options.Flow}
}

// chainTargets finds the inbounds that chain outbounds on this daemon dial, and the system user each needs.
func (s *Snapshot) chainTargets() map[int64][]spec.User {
	out := map[int64][]spec.User{}
	for _, outs := range s.Outbounds {
		for _, o := range outs {
			if o.TargetInboundID == nil {
				continue
			}
			target := *o.TargetInboundID
			sys := spec.SystemUser(s.Secret, systemName(o.DaemonID, target))
			sys.Password = passwordFor(s.Inbounds[target], sys)
			if !slices.ContainsFunc(out[target], func(u spec.User) bool { return u.Name == sys.Name }) {
				out[target] = append(out[target], sys)
			}
		}
	}
	return out
}

// systemName is the label of the user a bridge daemon authenticates as.
func systemName(bridgeDaemon, target int64) string {
	return fmt.Sprintf("bridge-%d-%d", bridgeDaemon, target)
}

// passwordFor makes a system user's password fit the cipher of the target inbound.
func passwordFor(in db.Inbound, u spec.User) string {
	_, pass := spec.CredentialsFor(in.Protocol, in.Options.Method, u.UUID, u.Password)
	return pass
}

// outbounds renders the daemon's outbounds, always keeping direct and block available.
func (s *Snapshot) outbounds(d db.Daemon) ([]spec.Outbound, error) {
	var out []spec.Outbound
	for _, o := range s.Outbounds[d.ID] {
		so := spec.Outbound{Tag: o.Tag, Kind: o.Kind, Upstream: o.Upstream, Interface: o.Interface, Strategy: o.Strategy}
		if o.Kind == spec.OutWarp && o.Interface == "" {
			if s.Warp == nil {
				return nil, fmt.Errorf("outbound %s needs a WARP account, register one first", o.Tag)
			}
			so.Warp = warpOf(*s.Warp)
		}
		if o.TargetInboundID != nil {
			up, err := s.chainUpstream(d.ID, *o.TargetInboundID)
			if err != nil {
				return nil, fmt.Errorf("outbound %s: %w", o.Tag, err)
			}
			so.Kind, so.Upstream = spec.OutProxy, &up
		}
		out = append(out, so)
	}
	if !hasTag(out, "direct") {
		out = append(out, spec.Outbound{Tag: "direct", Kind: spec.OutDirect})
	}
	if !hasTag(out, "block") {
		out = append(out, spec.Outbound{Tag: "block", Kind: spec.OutBlock})
	}
	return out, nil
}

// chainUpstream builds the upstream that reaches one of our own inbounds as a bridge.
func (s *Snapshot) chainUpstream(bridgeDaemon, target int64) (spec.Upstream, error) {
	in, ok := s.Inbounds[target]
	if !ok {
		return spec.Upstream{}, fmt.Errorf("target inbound %d no longer exists", target)
	}
	node := s.Nodes[s.Daemons[in.DaemonID].NodeID]
	sys := spec.SystemUser(s.Secret, systemName(bridgeDaemon, target))
	ep := share.Endpoint{Inbound: specInbound(in), Host: hostFor(s.Hosts[in.ID]), NodeAddress: node.Address, NodeName: node.Name}
	sys.Password = passwordFor(in, sys)
	return share.Upstream(ep, sys)
}

// specInbound is the stored inbound without users.
func specInbound(in db.Inbound) spec.Inbound {
	return spec.Inbound{
		Tag: in.Tag, Protocol: in.Protocol, Listen: in.Listen, Port: int(in.Port),
		Transport: in.Transport, Security: in.Security, Options: in.Options, Sniffing: in.Sniffing, Forward: in.Forward,
	}
}

// hostFor picks the first enabled direct host of an inbound, if there is one.
func hostFor(hosts []db.Host) share.Host {
	for _, h := range hosts {
		if h.Enabled && h.BridgeInboundID == nil {
			return HostOf(h)
		}
	}
	return share.Host{}
}

// HostOf converts a stored host into the share form.
func HostOf(h db.Host) share.Host {
	out := share.Host{
		Remark: h.Remark, Address: h.Address, SNI: h.Sni, Host: h.Host, Path: h.Path, ALPN: h.Alpn,
		Fingerprint: h.Fingerprint, Insecure: h.Insecure, Mux: h.Mux, Fragment: h.Fragment,
	}
	if h.Port != nil {
		out.Port = int(*h.Port)
	}
	return out
}

// rules merges the panel wide defaults, global rules and the daemon's own rules in priority order.
func (s *Snapshot) rules(d db.Daemon, outs []spec.Outbound) []spec.Rule {
	var out []spec.Rule
	r := s.Routing
	if r.BlockPrivate {
		out = append(out, spec.Rule{Name: "block private", IPCIDR: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7"}, Outbound: "block"})
	}
	if r.BlockBittorrent {
		out = append(out, spec.Rule{Name: "block bittorrent", Protocol: []string{"bittorrent"}, Outbound: "block"})
	}
	if r.BlockQUIC {
		out = append(out, spec.Rule{Name: "block quic", Network: "udp", Port: []string{"443"}, Outbound: "block"})
	}
	if r.BlockAds {
		out = append(out, spec.Rule{Name: "block ads", GeoSite: []string{"category-ads-all"}, Outbound: "block"})
	}
	if len(r.DirectDomains) > 0 {
		out = append(out, spec.Rule{Name: "direct domains", DomainSuffix: r.DirectDomains, Outbound: "direct"})
	}

	for _, rule := range s.Rules {
		if !rule.Enabled || (rule.DaemonID != nil && *rule.DaemonID != d.ID) || !hasTag(outs, rule.Outbound) {
			continue
		}
		m := rule.Match
		m.Name, m.Outbound = rule.Name, rule.Outbound
		out = append(out, m)
	}
	return out
}

// hasTag reports whether an outbound with the tag exists.
func hasTag(outs []spec.Outbound, tag string) bool {
	return slices.ContainsFunc(outs, func(o spec.Outbound) bool { return o.Tag == tag })
}

// Hash fingerprints a spec ignoring its revision, so only real changes bump the revision.
func Hash(d spec.Daemon) string {
	d.Revision = 0
	raw, _ := json.Marshal(d)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// warpOf turns a registered account into what a core dials.
func warpOf(a warp.Account) *spec.Warp {
	var addrs []string
	if a.AddressV4 != "" {
		addrs = append(addrs, a.AddressV4+"/32")
	}
	if a.AddressV6 != "" {
		addrs = append(addrs, a.AddressV6+"/128")
	}
	return &spec.Warp{PrivateKey: a.PrivateKey, PeerKey: a.PeerKey, Addresses: addrs, Endpoint: a.Endpoint, Reserved: a.Reserved}
}

// InternalPort is the loopback port an inbound listens on while an edge daemon fronts it.
func InternalPort(inboundID int64) int { return 30000 + int(inboundID%30000) }

// edgeNames lists the server names an inbound should be reachable by through an edge.
func edgeNames(in db.Inbound) []string {
	if len(in.EdgeSni) > 0 {
		return in.EdgeSni
	}
	sec := in.Security
	switch {
	case sec.Type == spec.SecurityReality && sec.Reality != nil:
		return sec.Reality.ServerNames
	case sec.ACME != nil && sec.ACME.Domain != "":
		return []string{sec.ACME.Domain}
	case sec.SNI != "":
		return []string{sec.SNI}
	}
	return nil
}

// buildEdge assembles the routing table of an edge daemon from the inbounds placed behind it.
func (s *Snapshot) buildEdge(d db.Daemon) (spec.Daemon, error) {
	e := &spec.Edge{Listen: d.EdgeListen, Default: d.EdgeDefault}
	var ids []int64
	for id, in := range s.Inbounds {
		if in.EdgeDaemonID != nil && *in.EdgeDaemonID == d.ID && in.Enabled {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)

	for _, id := range ids {
		in := s.Inbounds[id]
		names := edgeNames(in)
		if len(names) == 0 {
			return spec.Daemon{}, fmt.Errorf("inbound %s sits behind the edge but has no server name to match on", in.Tag)
		}
		e.Routes = append(e.Routes, spec.EdgeRoute{
			Name: in.Tag, SNI: names, Target: fmt.Sprintf("127.0.0.1:%d", InternalPort(in.ID)),
			Proxy: s.Daemons[in.DaemonID].Kind == "xray",
		})
	}
	return spec.Daemon{Kind: d.Kind, Edge: e, RawPatch: d.RawPatch}, nil
}

// portClash makes sure no two daemons on one node try to listen on the same public port.
func (s *Snapshot) portClash(d db.Daemon, mine []spec.Inbound) error {
	node := d.NodeID
	for _, other := range s.Daemons {
		if other.ID == d.ID || other.NodeID != node || !other.Enabled || other.Kind != "edge" {
			continue
		}
		for _, l := range other.EdgeListen {
			_, port, err := net.SplitHostPort(l)
			if err != nil {
				continue
			}
			for _, in := range mine {
				if in.Network() == "tcp" && !in.IsLoopback() && strconv.Itoa(in.Port) == port {
					return fmt.Errorf("inbound %s wants port %s, which the edge daemon %s already listens on: put the inbound behind it or change the port", in.Tag, port, other.Name)
				}
			}
		}
	}
	return nil
}
