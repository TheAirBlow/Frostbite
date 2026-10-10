package singbox

import (
	"fmt"
	"net"
	"strconv"

	"frostbite/internal/spec"
)

// Outbound renders one non-block outbound in sing-box's format.
func Outbound(o spec.Outbound, resolver, strategy string) (map[string]any, error) {
	switch o.Kind {
	case spec.OutDirect, spec.OutWarp:
		m := map[string]any{"type": "direct", "tag": o.Tag}
		iface := o.Interface
		if o.Kind == spec.OutWarp && iface == "" {
			iface = "warp"
		}
		if iface != "" {
			m["bind_interface"] = iface
		}
		if resolver != "" {
			if o.Strategy != "" {
				strategy = o.Strategy
			}
			m["domain_resolver"] = map[string]any{"server": resolver, "strategy": strategy}
		}
		return m, nil
	case spec.OutProxy:
		if o.Upstream == nil {
			return nil, fmt.Errorf("upstream is missing")
		}
		return OutboundFor(*o.Upstream, o.Tag)
	}
	return nil, fmt.Errorf("outbound kind %s is not supported by sing-box", o.Kind)
}

// OutboundsFor renders everything one upstream needs, which is two outbounds for shadowtls.
func OutboundsFor(u spec.Upstream, tag string) ([]map[string]any, error) {
	if u.Protocol != spec.ProtoShadowTLS {
		m, err := OutboundFor(u, tag)
		return []map[string]any{m}, err
	}
	if u.Inner == nil {
		return nil, fmt.Errorf("shadowtls has nothing behind it")
	}
	host, _, err := splitHostPort(u.Options.Handshake)
	if err != nil {
		return nil, fmt.Errorf("handshake server: %w", err)
	}
	stls := tag + " (shadowtls)"
	outer := map[string]any{
		"type": "shadowtls", "tag": stls, "server": u.Address, "server_port": u.Port,
		"version": 3, "password": u.Password,
		"tls": map[string]any{"enabled": true, "server_name": host, "utls": map[string]any{"enabled": true, "fingerprint": "chrome"}},
	}
	in := *u.Inner
	in.Address, in.Port = u.Address, u.Port
	inner, err := OutboundFor(in, tag)
	if err != nil {
		return nil, err
	}
	inner["detour"] = stls
	return []map[string]any{inner, outer}, nil
}

// OutboundFor renders a client side outbound for an upstream. Subscriptions use it too.
func OutboundFor(u spec.Upstream, tag string) (map[string]any, error) {
	if u.Protocol == spec.ProtoWireGuard {
		return nil, fmt.Errorf("wireguard is an endpoint in sing-box, use EndpointFor")
	}
	m := map[string]any{"tag": tag, "server": u.Address, "server_port": u.Port}
	switch u.Protocol {
	case spec.ProtoVLESS:
		m["type"], m["uuid"], m["flow"], m["packet_encoding"] = "vless", u.UUID, u.Options.Flow, "xudp"
	case spec.ProtoVMess:
		m["type"], m["uuid"], m["security"] = "vmess", u.UUID, "auto"
	case spec.ProtoTrojan:
		m["type"], m["password"] = "trojan", u.Password
	case spec.ProtoShadowsocks:
		m["type"], m["method"], m["password"] = "shadowsocks", u.Options.Method, u.Password
	case spec.ProtoHysteria2:
		m["type"], m["password"] = "hysteria2", u.Password
		if u.Options.Obfs != "" {
			m["obfs"] = map[string]any{"type": u.Options.Obfs, "password": u.Options.ObfsPass}
		}
		m["up_mbps"], m["down_mbps"] = u.Options.UpMbps, u.Options.DownMbps
		if u.Options.Ports != "" {
			m["server_ports"] = []string{replaceDash(u.Options.Ports)}
		}
	case spec.ProtoTUIC:
		m["type"], m["uuid"], m["password"] = "tuic", u.UUID, u.Password
		m["congestion_control"] = u.Options.CongestCtl
		m["zero_rtt_handshake"] = u.Options.ZeroRTT
	case spec.ProtoAnyTLS:
		m["type"], m["password"] = "anytls", u.Password
	case spec.ProtoSOCKS, spec.ProtoMixed:
		m["type"], m["version"] = "socks", "5"
		m["username"], m["password"] = u.Username, u.Password
	case spec.ProtoNaive:
		m["type"], m["username"], m["password"] = "naive", u.Username, u.Password
	case spec.ProtoHTTP:
		m["type"], m["username"], m["password"] = "http", u.Username, u.Password
	default:
		return nil, fmt.Errorf("protocol %s is not supported by sing-box", u.Protocol)
	}

	if t := transport(u.Transport); t != nil {
		m["transport"] = t
	}
	if tls := clientTLS(u); tls != nil {
		m["tls"] = tls
	}
	if mux := u.Options.Mux; mux != nil && mux.Enabled {
		proto := mux.Protocol
		if proto == "" {
			proto = "h2mux"
		}
		m["multiplex"] = map[string]any{"enabled": true, "protocol": proto, "padding": mux.Padding}
	}
	return m, nil
}

// clientTLS renders the outbound tls block.
func clientTLS(u spec.Upstream) map[string]any {
	s := u.Security
	needsTLS := s.Type == spec.SecurityTLS || s.Type == spec.SecurityReality
	switch u.Protocol {
	case spec.ProtoHysteria2, spec.ProtoTUIC, spec.ProtoAnyTLS, spec.ProtoNaive:
		needsTLS = true
	}
	if !needsTLS {
		return nil
	}
	m := map[string]any{"enabled": true, "server_name": s.SNI, "alpn": s.ALPN, "insecure": s.Insecure}
	fp := s.Fingerprint
	if s.Type == spec.SecurityReality && fp == "" {
		fp = "chrome"
	}
	if fp != "" {
		m["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	if s.Type == spec.SecurityReality && s.Reality != nil {
		r := s.Reality
		sid := ""
		if len(r.ShortIDs) > 0 {
			sid = r.ShortIDs[0]
		}
		if m["server_name"] == "" && len(r.ServerNames) > 0 {
			m["server_name"] = r.ServerNames[0]
		}
		m["reality"] = map[string]any{"enabled": true, "public_key": r.PublicKey, "short_id": sid}
	}
	if s.ECHConfig != "" {
		m["ech"] = map[string]any{"enabled": true, "config": []string{s.ECHConfig}}
	}
	return m
}

// splitHostPort parses host:port into the pieces sing-box wants.
func splitHostPort(addr string) (string, int, error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, err
	}
	return h, n, nil
}

// replaceDash turns 20000-30000 into the 20000:30000 form sing-box expects.
func replaceDash(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c == '-' {
			out[i] = ':'
		}
	}
	return string(out)
}

// EndpointFor renders a client side WireGuard profile, which sing-box treats as an endpoint rather than an outbound.
func EndpointFor(u spec.Upstream, tag string) (map[string]any, error) {
	if u.Protocol != spec.ProtoWireGuard {
		return nil, fmt.Errorf("%s is not a wireguard profile", u.Protocol)
	}
	mtu := u.Options.WGMTU
	if mtu == 0 {
		mtu = 1420
	}
	return map[string]any{
		"type": "wireguard", "tag": tag, "system": false, "mtu": mtu, "address": []string{u.Options.WGAddress + "/32"}, "private_key": u.Password,
		"peers": []any{map[string]any{"address": u.Address, "port": u.Port, "public_key": u.Options.WGPublic, "allowed_ips": []string{"0.0.0.0/0", "::/0"}, "persistent_keepalive_interval": 25}},
	}, nil
}
