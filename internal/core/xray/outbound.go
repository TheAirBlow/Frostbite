package xray

import (
	"fmt"

	"frostbite/internal/spec"
)

// Outbound renders one outbound in xray's format.
func Outbound(o spec.Outbound) (map[string]any, error) {
	switch o.Kind {
	case spec.OutDirect:
		m := map[string]any{"tag": o.Tag, "protocol": "freedom", "settings": map[string]any{"domainStrategy": freedomStrategy(o.Strategy)}}
		if o.Interface != "" {
			m["streamSettings"] = map[string]any{"sockopt": map[string]any{"interface": o.Interface}}
		}
		return m, nil
	case spec.OutBlock:
		return map[string]any{"tag": o.Tag, "protocol": "blackhole"}, nil
	case spec.OutWarp:
		if o.Warp != nil {
			return wireguard(o.Tag, *o.Warp), nil
		}
		iface := o.Interface
		if iface == "" {
			iface = "warp"
		}
		return map[string]any{
			"tag": o.Tag, "protocol": "freedom",
			"streamSettings": map[string]any{"sockopt": map[string]any{"interface": iface}},
		}, nil
	case spec.OutProxy:
		if o.Upstream == nil {
			return nil, fmt.Errorf("upstream is missing")
		}
		return OutboundFor(*o.Upstream, o.Tag)
	}
	return nil, fmt.Errorf("outbound kind %s is not supported by xray", o.Kind)
}

// freedomStrategy maps the neutral strategy to xray's.
func freedomStrategy(s string) string {
	switch s {
	case "ipv4_only", "prefer_ipv4":
		return "UseIPv4"
	case "ipv6_only", "prefer_ipv6":
		return "UseIPv6"
	}
	return "AsIs"
}

// OutboundFor renders a client side outbound for an upstream. Subscriptions use it too.
func OutboundFor(u spec.Upstream, tag string) (map[string]any, error) {
	m := map[string]any{"tag": tag}
	switch u.Protocol {
	case spec.ProtoVLESS:
		m["protocol"] = "vless"
		m["settings"] = map[string]any{"vnext": []any{map[string]any{
			"address": u.Address, "port": u.Port,
			"users": []any{map[string]any{"id": u.UUID, "encryption": "none", "flow": u.Options.Flow}},
		}}}
	case spec.ProtoVMess:
		m["protocol"] = "vmess"
		m["settings"] = map[string]any{"vnext": []any{map[string]any{
			"address": u.Address, "port": u.Port,
			"users": []any{map[string]any{"id": u.UUID, "security": "auto"}},
		}}}
	case spec.ProtoTrojan:
		m["protocol"] = "trojan"
		m["settings"] = map[string]any{"servers": []any{map[string]any{"address": u.Address, "port": u.Port, "password": u.Password}}}
	case spec.ProtoShadowsocks:
		m["protocol"] = "shadowsocks"
		m["settings"] = map[string]any{"servers": []any{map[string]any{
			"address": u.Address, "port": u.Port, "method": u.Options.Method, "password": u.Password,
		}}}
	case spec.ProtoWireGuard:
		mtu := u.Options.WGMTU
		if mtu == 0 {
			mtu = 1420
		}
		return map[string]any{
			"tag": tag, "protocol": "wireguard",
			"settings": map[string]any{
				"secretKey": u.Password, "address": []string{u.Options.WGAddress + "/32"}, "mtu": mtu,
				"peers": []any{map[string]any{"publicKey": u.Options.WGPublic, "endpoint": fmt.Sprintf("%s:%d", u.Address, u.Port), "allowedIPs": []string{"0.0.0.0/0", "::/0"}}},
			},
		}, nil
	case spec.ProtoSOCKS, spec.ProtoHTTP, spec.ProtoMixed:
		proto := u.Protocol
		if proto == spec.ProtoMixed {
			proto = spec.ProtoSOCKS
		}
		srv := map[string]any{"address": u.Address, "port": u.Port}
		if u.Username != "" {
			srv["users"] = []any{map[string]any{"user": u.Username, "pass": u.Password}}
		}
		m["protocol"] = proto
		m["settings"] = map[string]any{"servers": []any{srv}}
	default:
		return nil, fmt.Errorf("protocol %s is not supported by xray", u.Protocol)
	}
	m["streamSettings"] = streamSettings(u.Transport, u.Security, false)
	if u.Options.Mux != nil && u.Options.Mux.Enabled {
		m["mux"] = map[string]any{"enabled": true, "concurrency": max(u.Options.Mux.Concurrency, 8)}
	}
	return m, nil
}

// wireguard renders a WireGuard exit.
func wireguard(tag string, w spec.Warp) map[string]any {
	mtu := w.MTU
	if mtu == 0 {
		mtu = 1280
	}
	return map[string]any{
		"tag": tag, "protocol": "wireguard",
		"settings": map[string]any{
			"secretKey": w.PrivateKey, "address": w.Addresses, "mtu": mtu, "reserved": w.Reserved[:],
			"peers": []any{map[string]any{"publicKey": w.PeerKey, "endpoint": w.Endpoint, "allowedIPs": []string{"0.0.0.0/0", "::/0"}}},
		},
	}
}
