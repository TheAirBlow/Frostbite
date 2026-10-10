package singbox

import (
	"fmt"
	"strings"

	"frostbite/internal/spec"
)

// Inbound renders one inbound in sing-box's format.
func Inbound(in spec.Inbound) (map[string]any, error) {
	listen := in.Listen
	if listen == "" {
		listen = "::"
	}
	m := map[string]any{"tag": in.Tag, "listen": listen, "listen_port": in.Port}

	switch in.Protocol {
	case spec.ProtoVLESS:
		users := make([]any, 0, len(in.Users))
		for _, u := range in.Users {
			users = append(users, map[string]any{"name": u.Name, "uuid": u.UUID, "flow": flowOf(in, u)})
		}
		m["type"], m["users"] = "vless", users
	case spec.ProtoVMess:
		users := make([]any, 0, len(in.Users))
		for _, u := range in.Users {
			users = append(users, map[string]any{"name": u.Name, "uuid": u.UUID, "alterId": 0})
		}
		m["type"], m["users"] = "vmess", users
	case spec.ProtoTrojan, spec.ProtoAnyTLS, spec.ProtoHysteria2:
		m["type"] = string(in.Protocol)
		m["users"] = passwordUsers(in)
	case spec.ProtoShadowsocks:
		m["type"], m["method"] = "shadowsocks", in.Options.Method
		if strings.HasPrefix(in.Options.Method, "2022-") {
			m["password"] = in.Options.ServerKey
		}
		m["users"] = passwordUsers(in)
	case spec.ProtoTUIC:
		users := make([]any, 0, len(in.Users))
		for _, u := range in.Users {
			users = append(users, map[string]any{"name": u.Name, "uuid": u.UUID, "password": u.Password})
		}
		m["type"], m["users"] = "tuic", users
		m["congestion_control"] = in.Options.CongestCtl
		m["zero_rtt_handshake"] = in.Options.ZeroRTT
		m["heartbeat"] = in.Options.Heartbeat
	case spec.ProtoNaive:
		users := make([]any, 0, len(in.Users))
		for _, u := range in.Users {
			users = append(users, map[string]any{"username": u.Name, "password": u.Password})
		}
		m["type"], m["users"] = "naive", users
	case spec.ProtoShadowTLS:
		host, port, err := splitHostPort(in.Options.Handshake)
		if err != nil {
			return nil, fmt.Errorf("handshake server: %w", err)
		}
		m["type"], m["version"], m["strict_mode"] = "shadowtls", 3, true
		m["handshake"] = map[string]any{"server": host, "server_port": port}
		m["users"] = passwordUsers(in)
		m["detour"] = in.Options.STLSDetour
	case spec.ProtoSOCKS, spec.ProtoHTTP, spec.ProtoMixed:
		m["type"] = string(in.Protocol)
		if in.Options.Auth {
			users := make([]any, 0, len(in.Users))
			for _, u := range in.Users {
				users = append(users, map[string]any{"username": u.Name, "password": u.Password})
			}
			m["users"] = users
		}
	case spec.ProtoForward:
		if in.Forward == nil {
			return nil, fmt.Errorf("forward target is missing")
		}
		m["type"] = "direct"
		m["override_address"] = in.Forward.Address
		m["override_port"] = in.Forward.Port
		if n := in.Forward.Network; n == "tcp" || n == "udp" {
			m["network"] = n
		}
	default:
		return nil, fmt.Errorf("protocol %s is not supported by sing-box", in.Protocol)
	}

	switch in.Protocol {
	case spec.ProtoForward, spec.ProtoShadowTLS:
	default:
		if t := transport(in.Transport); t != nil {
			m["transport"] = t
		}
		if tls := serverTLS(in); tls != nil {
			m["tls"] = tls
		}
		if mux := in.Options.Mux; mux != nil && mux.Enabled {
			m["multiplex"] = map[string]any{"enabled": true}
		}
	}

	if in.Protocol == spec.ProtoHysteria2 {
		o := in.Options
		m["up_mbps"], m["down_mbps"] = o.UpMbps, o.DownMbps
		if o.Obfs != "" {
			m["obfs"] = map[string]any{"type": o.Obfs, "password": o.ObfsPass}
		}
		if o.Masquerade != "" {
			m["masquerade"] = o.Masquerade
		}
	}
	if in.Protocol == spec.ProtoAnyTLS && in.Options.PaddingSch != "" {
		m["padding_scheme"] = strings.Split(in.Options.PaddingSch, "\n")
	}
	return m, nil
}

// passwordUsers lists name+password users, the shape most sing-box inbounds share.
func passwordUsers(in spec.Inbound) []any {
	users := make([]any, 0, len(in.Users))
	for _, u := range in.Users {
		users = append(users, map[string]any{"name": u.Name, "password": u.Password})
	}
	return users
}

// flowOf only keeps vision where it can work, which is raw tcp over tls or reality.
func flowOf(in spec.Inbound, u spec.User) string {
	flow := u.Flow
	if flow == "" {
		flow = in.Options.Flow
	}
	if in.Transport.Type != "" && in.Transport.Type != spec.TransportTCP {
		return ""
	}
	if in.Security.Type != spec.SecurityTLS && in.Security.Type != spec.SecurityReality {
		return ""
	}
	return flow
}

// transport renders the v2ray style transport block, or nil for plain tcp.
func transport(t spec.Transport) map[string]any {
	switch t.Type {
	case spec.TransportWS:
		m := map[string]any{"type": "ws", "path": t.Path, "headers": hostHeaders(t)}
		if t.EarlyData > 0 {
			m["max_early_data"] = t.EarlyData
			m["early_data_header_name"] = "Sec-WebSocket-Protocol"
		}
		return m
	case spec.TransportGRPC:
		return map[string]any{"type": "grpc", "service_name": t.ServiceName}
	case spec.TransportHTTPUpgrade:
		return map[string]any{"type": "httpupgrade", "path": t.Path, "host": t.Host, "headers": t.Headers}
	}
	return nil
}

// hostHeaders folds the host shortcut into the header map.
func hostHeaders(t spec.Transport) map[string]any {
	out := map[string]any{}
	for k, v := range t.Headers {
		out[k] = v
	}
	if t.Host != "" {
		out["Host"] = t.Host
	}
	return out
}

// serverTLS renders the inbound tls block, or nil when security is off.
func serverTLS(in spec.Inbound) map[string]any {
	s := in.Security
	switch s.Type {
	case spec.SecurityTLS:
		m := map[string]any{"enabled": true, "server_name": s.SNI, "alpn": s.ALPN, "certificate_path": s.CertPath, "key_path": s.KeyPath}
		if s.ECHKey != "" {
			m["ech"] = map[string]any{"enabled": true, "key": strings.Split(s.ECHKey, "\n")}
		}
		return m
	case spec.SecurityReality:
		r := s.Reality
		if r == nil {
			return nil
		}
		host, port, err := splitHostPort(r.Dest)
		if err != nil {
			return nil
		}
		name := ""
		if len(r.ServerNames) > 0 {
			name = r.ServerNames[0]
		}
		return map[string]any{
			"enabled": true, "server_name": name,
			"reality": map[string]any{
				"enabled":     true,
				"handshake":   map[string]any{"server": host, "server_port": port},
				"private_key": r.PrivateKey,
				"short_id":    append([]string{""}, r.ShortIDs...),
			},
		}
	}
	return nil
}

// FlowOf is the vision flow a user ends up with on an inbound, empty where it cannot work.
func FlowOf(in spec.Inbound, u spec.User) string { return flowOf(in, u) }
