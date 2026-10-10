// Package singbox renders specs into sing-box configs (1.12 format).
package singbox

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"frostbite/internal/core"
	"frostbite/internal/keys"
	"frostbite/internal/spec"
)

func init() {
	core.Register(core.Descriptor{
		Kind:        "singbox",
		DisplayName: "sing-box",
		Caps: core.Capabilities{
			Protocols: []string{
				spec.ProtoVLESS, spec.ProtoVMess, spec.ProtoTrojan, spec.ProtoShadowsocks, spec.ProtoHysteria2,
				spec.ProtoTUIC, spec.ProtoAnyTLS, spec.ProtoNaive, spec.ProtoSOCKS,
				spec.ProtoHTTP, spec.ProtoMixed, spec.ProtoForward, spec.ProtoWireGuard,
			},
			Transports: []string{spec.TransportTCP, spec.TransportWS, spec.TransportGRPC, spec.TransportHTTPUpgrade},
			Securities: []string{spec.SecurityNone, spec.SecurityTLS, spec.SecurityReality},
			Outbounds:  []string{spec.OutDirect, spec.OutBlock, spec.OutProxy, spec.OutWarp},
			HotUsers:   true, // every protocol here changes users without a restart
		},
		Render: Render,
	})
}

// Render builds the full sing-box config for d.
func Render(d spec.Daemon) ([]byte, error) {
	cfg := map[string]any{"log": map[string]any{"level": logLevel(d.Log.Level), "timestamp": true}}

	resolver := ""
	if dns, tag := renderDNS(d.DNS); dns != nil {
		cfg["dns"] = dns
		resolver = tag
	}

	var inbounds, endpoints []any
	var sniffTags []string
	for _, in := range d.Inbounds {
		if in.Protocol == spec.ProtoWireGuard {
			ep, err := wireguardServer(in)
			if err != nil {
				return nil, fmt.Errorf("inbound %s: %w", in.Tag, err)
			}
			endpoints = append(endpoints, ep)
			if in.Sniffing.Enabled {
				sniffTags = append(sniffTags, in.Tag)
			}
			continue
		}
		m, err := Inbound(in)
		if err != nil {
			return nil, fmt.Errorf("inbound %s: %w", in.Tag, err)
		}
		if err := core.ApplyPatch(m, in.RawPatch); err != nil {
			return nil, fmt.Errorf("inbound %s: %w", in.Tag, err)
		}
		inbounds = append(inbounds, m)
		if in.Sniffing.Enabled {
			sniffTags = append(sniffTags, in.Tag)
		}
	}
	cfg["inbounds"] = inbounds

	blocked := map[string]bool{}
	var outbounds []any
	outs := core.Ordered(d.Outbounds, func(o spec.Outbound) string { return o.Tag }, d.Final)
	for _, o := range outs {
		if o.Kind == spec.OutBlock {
			blocked[o.Tag] = true
			continue
		}
		if o.Kind == spec.OutWarp && o.Warp != nil {
			endpoints = append(endpoints, wireguardEndpoint(o.Tag, *o.Warp))
			continue
		}
		m, err := Outbound(o, resolver, d.DNS.Strategy)
		if err != nil {
			return nil, fmt.Errorf("outbound %s: %w", o.Tag, err)
		}
		outbounds = append(outbounds, m)
	}
	if len(outbounds) == 0 {
		outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})
	}
	cfg["outbounds"] = outbounds
	if len(endpoints) > 0 {
		cfg["endpoints"] = endpoints
	}

	var rules []any
	if len(sniffTags) > 0 {
		rules = append(rules, map[string]any{"inbound": sniffTags, "action": "sniff"})
	}
	sets := map[string]any{}
	for _, r := range d.Rules {
		rules = append(rules, renderRule(r, blocked, sets))
	}
	if blocked[d.Final] {
		rules = append(rules, map[string]any{"action": "reject"})
	}

	route := map[string]any{"rules": rules}
	if !blocked[d.Final] && d.Final != "" {
		route["final"] = d.Final
	}
	if resolver != "" {
		route["default_domain_resolver"] = resolver
	}
	if len(sets) > 0 {
		list := make([]any, 0, len(sets))
		for _, k := range sortedKeys(sets) {
			list = append(list, sets[k])
		}
		route["rule_set"] = list
	}
	cfg["route"] = route

	if err := core.ApplyPatch(cfg, d.RawPatch); err != nil {
		return nil, err
	}
	core.Prune(cfg)
	return json.MarshalIndent(cfg, "", "  ")
}

// logLevel maps the neutral level to sing-box's names.
func logLevel(l string) string {
	switch l {
	case "":
		return "warn"
	case "warning":
		return "warn"
	case "none":
		return "panic"
	}
	return l
}

// renderDNS builds sing-box's dns block and the tag of the first server.
func renderDNS(d spec.DNS) (map[string]any, string) {
	if len(d.Servers) == 0 {
		return nil, ""
	}
	servers := make([]any, 0, len(d.Servers))
	for i, s := range d.Servers {
		servers = append(servers, dnsServer(fmt.Sprintf("dns%d", i), s))
	}
	out := map[string]any{"servers": servers}
	if d.Strategy != "" {
		out["strategy"] = d.Strategy
	}
	return out, "dns0"
}

// dnsServer parses a server string such as 1.1.1.1, tls://dns.google or https://host/dns-query.
func dnsServer(tag, raw string) map[string]any {
	m := map[string]any{"tag": tag}
	if !strings.Contains(raw, "://") {
		m["type"] = "udp"
		m["server"] = raw
		return m
	}
	u, err := url.Parse(raw)
	if err != nil {
		m["type"] = "udp"
		m["server"] = raw
		return m
	}
	m["type"] = u.Scheme
	m["server"] = u.Hostname()
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			m["server_port"] = n
		}
	}
	if u.Scheme == "https" && u.Path != "" {
		m["path"] = u.Path
	}
	return m
}

// renderRule builds one route rule, registering any rule sets it needs.
func renderRule(r spec.Rule, blocked map[string]bool, sets map[string]any) map[string]any {
	m := map[string]any{
		"inbound":        r.InboundTags,
		"auth_user":      r.Users,
		"domain":         r.Domain,
		"domain_suffix":  r.DomainSuffix,
		"domain_keyword": r.DomainKw,
		"ip_cidr":        r.IPCIDR,
		"network":        r.Network,
		"protocol":       r.Protocol,
	}
	if len(r.Port) > 0 {
		var ports []int
		var ranges []string
		for _, p := range r.Port {
			if n, err := strconv.Atoi(p); err == nil {
				ports = append(ports, n)
			} else {
				ranges = append(ranges, strings.ReplaceAll(p, "-", ":"))
			}
		}
		m["port"] = ports
		m["port_range"] = ranges
	}

	var ruleSets []string
	for _, g := range r.GeoSite {
		tag := "geosite-" + g
		sets[tag] = remoteSet(tag, "sing-geosite")
		ruleSets = append(ruleSets, tag)
	}
	for _, g := range r.GeoIP {
		tag := "geoip-" + g
		sets[tag] = remoteSet(tag, "sing-geoip")
		ruleSets = append(ruleSets, tag)
	}
	m["rule_set"] = ruleSets

	if blocked[r.Outbound] {
		m["action"] = "reject"
	} else {
		m["action"] = "route"
		m["outbound"] = r.Outbound
	}
	return m
}

// remoteSet points at a published SagerNet rule set.
func remoteSet(tag, repo string) map[string]any {
	return map[string]any{
		"tag": tag, "type": "remote", "format": "binary",
		"url":             "https://raw.githubusercontent.com/SagerNet/" + repo + "/rule-set/" + tag + ".srs",
		"update_interval": "7d",
	}
}

// sortedKeys returns map keys in a stable order so rendered configs do not churn.
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// Capabilities returns what this renderer supports.
func Capabilities() core.Capabilities { return core.Get("singbox").Caps }

// wireguardEndpoint renders a userspace WireGuard peer, which sing-box treats as something traffic can be routed to.
func wireguardEndpoint(tag string, w spec.Warp) map[string]any {
	host, port, _ := splitHostPort(w.Endpoint)
	mtu := w.MTU
	if mtu == 0 {
		mtu = 1280
	}
	return map[string]any{
		"type": "wireguard", "tag": tag, "system": false, "mtu": mtu, "address": w.Addresses, "private_key": w.PrivateKey,
		"peers": []any{map[string]any{
			"address": host, "port": port, "public_key": w.PeerKey, "allowed_ips": []string{"0.0.0.0/0", "::/0"}, "reserved": w.Reserved[:],
		}},
	}
}

// wireguardServer renders a WireGuard inbound: one peer per user, each limited to its own address.
func wireguardServer(in spec.Inbound) (map[string]any, error) {
	addr, err := spec.WGServerAddress(in.Options.WGSubnet)
	if err != nil {
		return nil, err
	}
	var peers []any
	for _, u := range in.Users {
		pub, err := keys.WireGuardPublic(u.Password)
		if err != nil {
			return nil, fmt.Errorf("user %s: %w", u.Name, err)
		}
		ip, err := spec.WGAddress(in.Options.WGSubnet, u.ID)
		if err != nil {
			return nil, err
		}
		peers = append(peers, map[string]any{"public_key": pub, "allowed_ips": []string{ip + "/32"}})
	}
	mtu := in.Options.WGMTU
	if mtu == 0 {
		mtu = 1420
	}
	return map[string]any{
		"type": "wireguard", "tag": in.Tag, "system": false, "mtu": mtu, "address": []string{addr},
		"private_key": in.Options.WGPrivate, "listen_port": in.Port, "peers": peers,
	}, nil
}
