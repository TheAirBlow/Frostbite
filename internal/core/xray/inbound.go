package xray

import (
	"fmt"
	"strings"

	"frostbite/internal/spec"
)

// Inbound renders one inbound in xray's format.
func Inbound(in spec.Inbound) (map[string]any, error) {
	listen := in.Listen
	if listen == "" {
		listen = "0.0.0.0"
	}
	m := map[string]any{"tag": in.Tag, "listen": listen, "port": in.Port}

	switch in.Protocol {
	case spec.ProtoVLESS:
		clients := make([]any, 0, len(in.Users))
		for _, u := range in.Users {
			clients = append(clients, map[string]any{"id": u.UUID, "email": u.Name, "flow": flowOf(in, u)})
		}
		m["protocol"] = "vless"
		m["settings"] = map[string]any{"clients": clients, "decryption": "none"}
	case spec.ProtoVMess:
		clients := make([]any, 0, len(in.Users))
		for _, u := range in.Users {
			clients = append(clients, map[string]any{"id": u.UUID, "email": u.Name})
		}
		m["protocol"] = "vmess"
		m["settings"] = map[string]any{"clients": clients}
	case spec.ProtoTrojan:
		clients := make([]any, 0, len(in.Users))
		for _, u := range in.Users {
			clients = append(clients, map[string]any{"password": u.Password, "email": u.Name})
		}
		m["protocol"] = "trojan"
		m["settings"] = map[string]any{"clients": clients}
	case spec.ProtoShadowsocks:
		m["protocol"] = "shadowsocks"
		m["settings"] = shadowsocks(in)
	case spec.ProtoSOCKS:
		m["protocol"] = "socks"
		m["settings"] = map[string]any{"auth": authMode(in), "accounts": accounts(in), "udp": true}
	case spec.ProtoHTTP:
		m["protocol"] = "http"
		m["settings"] = map[string]any{"accounts": accounts(in)}
	case spec.ProtoForward:
		if in.Forward == nil {
			return nil, fmt.Errorf("forward target is missing")
		}
		network := in.Forward.Network
		if network == "" {
			network = "tcp,udp"
		}
		m["protocol"] = "dokodemo-door"
		m["settings"] = map[string]any{"address": in.Forward.Address, "port": in.Forward.Port, "network": network}
	default:
		return nil, fmt.Errorf("protocol %s is not supported by xray", in.Protocol)
	}

	if in.Protocol != spec.ProtoForward {
		ss := streamSettings(in.Transport, in.Security, true)
		if in.Options.AcceptProxy {
			ss["sockopt"] = map[string]any{"acceptProxyProtocol": true}
		}
		m["streamSettings"] = ss
	}
	if in.Sniffing.Enabled {
		m["sniffing"] = map[string]any{
			"enabled":      true,
			"destOverride": []string{"http", "tls", "quic"},
			"routeOnly":    in.Sniffing.RouteOnly,
		}
	}
	return m, nil
}

// flowOf picks the vision flow only where it can work, which is raw tcp over tls or reality.
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

// shadowsocks renders shadowsocks settings, with per-user keys for the 2022 ciphers.
func shadowsocks(in spec.Inbound) map[string]any {
	s := map[string]any{"method": in.Options.Method, "network": "tcp,udp"}
	clients := make([]any, 0, len(in.Users))
	for _, u := range in.Users {
		c := map[string]any{"password": u.Password, "email": u.Name}
		if !strings.HasPrefix(in.Options.Method, "2022-") {
			c["method"] = in.Options.Method
		}
		clients = append(clients, c)
	}
	s["clients"] = clients
	if strings.HasPrefix(in.Options.Method, "2022-") {
		s["password"] = in.Options.ServerKey
	}
	return s
}

// authMode says whether a socks or http inbound asks for credentials.
func authMode(in spec.Inbound) string {
	if in.Options.Auth {
		return "password"
	}
	return "noauth"
}

// accounts lists credentials for socks and http inbounds.
func accounts(in spec.Inbound) []any {
	if !in.Options.Auth {
		return nil
	}
	out := make([]any, 0, len(in.Users))
	for _, u := range in.Users {
		out = append(out, map[string]any{"user": u.Name, "pass": u.Password})
	}
	return out
}

// streamSettings renders the transport and security layers. server picks which side of REALITY and TLS to fill in.
func streamSettings(t spec.Transport, s spec.Security, server bool) map[string]any {
	ss := map[string]any{}
	network := t.Type
	switch network {
	case "", spec.TransportTCP:
		network = "tcp"
	case spec.TransportKCP:
		network = "kcp"
		ss["kcpSettings"] = map[string]any{"seed": t.KCPSeed, "header": map[string]any{"type": "none"}}
	case spec.TransportWS:
		ws := map[string]any{"path": t.Path, "headers": mergeHost(t.Headers, t.Host)}
		if t.EarlyData > 0 {
			ws["maxEarlyData"] = t.EarlyData
		}
		ss["wsSettings"] = ws
	case spec.TransportGRPC:
		ss["grpcSettings"] = map[string]any{"serviceName": t.ServiceName}
	case spec.TransportHTTPUpgrade:
		ss["httpupgradeSettings"] = map[string]any{"path": t.Path, "host": t.Host, "headers": t.Headers}
	case spec.TransportXHTTP:
		mode := t.Mode
		if mode == "" {
			mode = "auto"
		}
		ss["xhttpSettings"] = map[string]any{"path": t.Path, "host": t.Host, "mode": mode, "headers": t.Headers}
	}
	ss["network"] = network

	switch s.Type {
	case spec.SecurityTLS:
		ss["security"] = "tls"
		tls := map[string]any{"serverName": s.SNI, "alpn": s.ALPN}
		if server {
			if s.CertPath != "" {
				tls["certificates"] = []any{map[string]any{"certificateFile": s.CertPath, "keyFile": s.KeyPath}}
			}
			if s.ECHKey != "" {
				tls["echServerKeys"] = s.ECHKey
			}
		} else {
			// xray dropped allowInsecure in 26.x and refuses configs that carry it
			tls["fingerprint"] = s.Fingerprint
			if s.ECHConfig != "" {
				tls["echConfigList"] = s.ECHConfig
			}
		}
		ss["tlsSettings"] = tls
	case spec.SecurityReality:
		ss["security"] = "reality"
		r := s.Reality
		if r == nil {
			break
		}
		if server {
			ss["realitySettings"] = map[string]any{
				"show": false, "dest": r.Dest, "xver": r.XVer, "serverNames": r.ServerNames,
				"privateKey": r.PrivateKey, "shortIds": append([]string{""}, r.ShortIDs...),
			}
		} else {
			name := ""
			if len(r.ServerNames) > 0 {
				name = r.ServerNames[0]
			}
			sid := ""
			if len(r.ShortIDs) > 0 {
				sid = r.ShortIDs[0]
			}
			ss["realitySettings"] = map[string]any{
				"serverName": name, "fingerprint": fpOr(s.Fingerprint), "publicKey": r.PublicKey,
				"shortId": sid, "spiderX": r.SpiderX,
			}
		}
	default:
		ss["security"] = "none"
	}
	return ss
}

// fpOr falls back to chrome, since reality clients refuse to run without a fingerprint.
func fpOr(fp string) string {
	if fp == "" {
		return "chrome"
	}
	return fp
}

// mergeHost folds the host shortcut into a header map.
func mergeHost(h map[string]string, host string) map[string]any {
	out := map[string]any{}
	for k, v := range h {
		out[k] = v
	}
	if host != "" {
		out["Host"] = host
	}
	return out
}
