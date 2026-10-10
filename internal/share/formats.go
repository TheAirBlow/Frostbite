package share

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"frostbite/internal/core"
	"frostbite/internal/core/singbox"
	"frostbite/internal/core/xray"
	"frostbite/internal/spec"
)

// Subscription formats.
const (
	FormatLinks   = "links"   // base64 list of share links
	FormatRaw     = "raw"     // plain list of share links
	FormatClash   = "clash"   // mihomo / clash meta yaml
	FormatSingbox = "singbox" // full sing-box client config
	FormatXray    = "xray"    // json array of xray client configs
)

// Formats lists every format the panel can serve.
var Formats = []string{FormatLinks, FormatRaw, FormatClash, FormatSingbox, FormatXray}

// uaRules map client names to the format they read best, first match wins.
var uaRules = []struct {
	re     *regexp.Regexp
	format string
}{
	{regexp.MustCompile(`(?i)clash|mihomo|stash|verge|flclash|koala`), FormatClash},
	{regexp.MustCompile(`(?i)sing-?box|sfa|sfi|sfm|karing`), FormatSingbox},
	{regexp.MustCompile(`(?i)v2rayn|v2rayng|nekobox|nekoray|streisand|happ|shadowrocket|hiddify|v2box|foxray|loon|surge`), FormatLinks},
}

// DetectFormat guesses the best format for a client, falling back to share links.
func DetectFormat(ua string) string {
	for _, r := range uaRules {
		if r.re.MatchString(ua) {
			return r.format
		}
	}
	return FormatLinks
}

// ContentType is what a format is served as.
func ContentType(format string) string {
	switch format {
	case FormatClash:
		return "text/yaml; charset=utf-8"
	case FormatSingbox, FormatXray:
		return "application/json; charset=utf-8"
	}
	return "text/plain; charset=utf-8"
}

// Render builds a subscription document. A non-empty patch is merged over the generated config.
func Render(format string, profiles []spec.Upstream, patch json.RawMessage) ([]byte, error) {
	switch format {
	case FormatRaw, FormatLinks:
		var lines []string
		for _, p := range profiles {
			if l, err := Link(p); err == nil {
				lines = append(lines, l)
			}
		}
		body := strings.Join(lines, "\n")
		if format == FormatLinks {
			return []byte(base64.StdEncoding.EncodeToString([]byte(body))), nil
		}
		return []byte(body), nil
	case FormatClash:
		return renderClash(profiles, patch)
	case FormatSingbox:
		return renderSingbox(profiles, patch)
	case FormatXray:
		return renderXray(profiles, patch)
	}
	return nil, fmt.Errorf("unknown format %q", format)
}

// renderSingbox builds a ready to run sing-box client config.
func renderSingbox(profiles []spec.Upstream, patch json.RawMessage) ([]byte, error) {
	var tags []string
	outbounds := []any{}
	endpoints := []any{}
	for _, p := range profiles {
		if p.Protocol == spec.ProtoWireGuard {
			ep, err := singbox.EndpointFor(p, p.Name)
			if err != nil {
				continue
			}
			endpoints = append(endpoints, core.Prune(ep))
			tags = append(tags, p.Name)
			continue
		}
		outs, err := singbox.OutboundsFor(p, p.Name)
		if err != nil {
			continue
		}
		for _, o := range outs {
			outbounds = append(outbounds, core.Prune(o))
		}
		tags = append(tags, p.Name)
	}
	if len(tags) == 0 {
		return nil, fmt.Errorf("no profile is usable with sing-box")
	}

	outbounds = append([]any{
		map[string]any{"type": "selector", "tag": "proxy", "outbounds": append([]string{"auto"}, tags...), "default": "auto"},
		map[string]any{"type": "urltest", "tag": "auto", "outbounds": tags, "url": "https://www.gstatic.com/generate_204", "interval": "3m"},
	}, outbounds...)
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})

	cfg := map[string]any{
		"log": map[string]any{"level": "warn"},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy"},
				map[string]any{"type": "local", "tag": "local"},
			},
			"final": "remote",
		},
		"inbounds": []any{
			map[string]any{"type": "tun", "tag": "tun-in", "address": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}, "auto_route": true, "strict_route": true},
			map[string]any{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080},
		},
		"outbounds": outbounds,
		"endpoints": endpoints,
		"route": map[string]any{
			"auto_detect_interface":   true,
			"default_domain_resolver": "local",
			"rules": []any{
				map[string]any{"action": "sniff"},
				map[string]any{"protocol": "dns", "action": "hijack-dns"},
				map[string]any{"ip_is_private": true, "outbound": "direct"},
			},
			"final": "proxy",
		},
	}
	if err := core.ApplyPatch(cfg, patch); err != nil {
		return nil, err
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// renderXray builds one xray client config per profile, in the array form v2rayN and friends import.
func renderXray(profiles []spec.Upstream, patch json.RawMessage) ([]byte, error) {
	var docs []any
	for _, p := range profiles {
		o, err := xray.OutboundFor(p, "proxy")
		if err != nil {
			continue
		}
		cfg := map[string]any{
			"remarks": p.Name,
			"log":     map[string]any{"loglevel": "warning"},
			"inbounds": []any{
				map[string]any{"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": map[string]any{"udp": true},
					"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}}},
				map[string]any{"tag": "http", "listen": "127.0.0.1", "port": 10809, "protocol": "http"},
			},
			"outbounds": []any{
				o,
				map[string]any{"tag": "direct", "protocol": "freedom"},
				map[string]any{"tag": "block", "protocol": "blackhole"},
			},
			"routing": map[string]any{"domainStrategy": "IPIfNonMatch", "rules": []any{
				map[string]any{"type": "field", "ip": []string{"geoip:private"}, "outboundTag": "direct"},
			}},
		}
		if err := core.ApplyPatch(cfg, patch); err != nil {
			return nil, err
		}
		docs = append(docs, core.Prune(cfg))
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("no profile is usable with xray")
	}
	return json.MarshalIndent(docs, "", "  ")
}

// renderClash builds a mihomo config with a url-test group.
func renderClash(profiles []spec.Upstream, patch json.RawMessage) ([]byte, error) {
	var proxies []any
	var names []string
	for _, p := range profiles {
		m := clashProxy(p)
		if m == nil {
			continue
		}
		proxies = append(proxies, m)
		names = append(names, p.Name)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no profile is usable with clash")
	}

	cfg := map[string]any{
		"mixed-port": 7890, "allow-lan": false, "mode": "rule", "log-level": "warning", "ipv6": true,
		"dns":     map[string]any{"enable": true, "enhanced-mode": "fake-ip", "nameserver": []string{"https://1.1.1.1/dns-query"}},
		"proxies": proxies,
		"proxy-groups": []any{
			map[string]any{"name": "proxy", "type": "select", "proxies": append([]string{"auto"}, names...)},
			map[string]any{"name": "auto", "type": "url-test", "proxies": names, "url": "https://www.gstatic.com/generate_204", "interval": 180},
		},
		"rules": []string{"GEOIP,PRIVATE,DIRECT,no-resolve", "MATCH,proxy"},
	}
	if err := core.ApplyPatch(cfg, patch); err != nil {
		return nil, err
	}
	return yaml.Marshal(cfg)
}

// clashProxy maps an upstream onto a mihomo proxy entry, or nil when mihomo cannot do it.
func clashProxy(p spec.Upstream) map[string]any {
	m := map[string]any{"name": p.Name, "server": p.Address, "port": p.Port, "udp": true}
	t, s := p.Transport, p.Security

	switch p.Protocol {
	case spec.ProtoShadowTLS:
		if p.Inner == nil {
			return nil
		}
		in := *p.Inner
		in.Name, in.Address, in.Port = p.Name, p.Address, p.Port
		m := clashProxy(in)
		host, _, err := net.SplitHostPort(p.Options.Handshake)
		if m == nil || err != nil {
			return nil
		}
		m["plugin"] = "shadow-tls"
		m["plugin-opts"] = map[string]any{"host": host, "password": p.Password, "version": 3}
		return m
	case spec.ProtoVLESS:
		m["type"], m["uuid"] = "vless", p.UUID
		if p.Options.Flow != "" {
			m["flow"] = p.Options.Flow
		}
		m["packet-encoding"] = "xudp"
	case spec.ProtoVMess:
		m["type"], m["uuid"], m["alterId"], m["cipher"] = "vmess", p.UUID, 0, "auto"
	case spec.ProtoTrojan:
		m["type"], m["password"] = "trojan", p.Password
	case spec.ProtoShadowsocks:
		m["type"], m["cipher"], m["password"] = "ss", p.Options.Method, p.Password
	case spec.ProtoHysteria2:
		m["type"], m["password"] = "hysteria2", p.Password
		if p.Options.Obfs != "" {
			m["obfs"], m["obfs-password"] = p.Options.Obfs, p.Options.ObfsPass
		}
		if p.Options.Ports != "" {
			m["ports"] = p.Options.Ports
		}
	case spec.ProtoTUIC:
		m["type"], m["uuid"], m["password"] = "tuic", p.UUID, p.Password
		m["alpn"] = []string{"h3"}
		m["udp-relay-mode"] = "native"
		if p.Options.CongestCtl != "" {
			m["congestion-controller"] = p.Options.CongestCtl
		}
	case spec.ProtoAnyTLS:
		m["type"], m["password"] = "anytls", p.Password
	case spec.ProtoWireGuard:
		m["type"], m["ip"], m["private-key"], m["public-key"] = "wireguard", p.Options.WGAddress, p.Password, p.Options.WGPublic
		if p.Options.WGMTU > 0 {
			m["mtu"] = p.Options.WGMTU
		}
		return core.Prune(m).(map[string]any)
	case spec.ProtoSOCKS, spec.ProtoMixed:
		m["type"], m["username"], m["password"] = "socks5", p.Username, p.Password
	default:
		return nil
	}

	if s.Type == spec.SecurityTLS || s.Type == spec.SecurityReality || p.Protocol == spec.ProtoHysteria2 || p.Protocol == spec.ProtoTUIC || p.Protocol == spec.ProtoAnyTLS {
		m["tls"] = true
		if s.SNI != "" {
			m["servername"] = s.SNI
			m["sni"] = s.SNI
		}
		if s.Insecure {
			m["skip-cert-verify"] = true
		}
		if len(s.ALPN) > 0 && p.Protocol != spec.ProtoTUIC {
			m["alpn"] = s.ALPN
		}
	}
	if s.Fingerprint != "" || s.Type == spec.SecurityReality {
		fp := s.Fingerprint
		if fp == "" {
			fp = "chrome"
		}
		m["client-fingerprint"] = fp
	}
	if s.Type == spec.SecurityReality && s.Reality != nil {
		r := s.Reality
		sid := ""
		if len(r.ShortIDs) > 0 {
			sid = r.ShortIDs[0]
		}
		if len(r.ServerNames) > 0 {
			m["servername"] = r.ServerNames[0]
		}
		m["reality-opts"] = map[string]any{"public-key": r.PublicKey, "short-id": sid}
	}

	switch t.Type {
	case spec.TransportWS:
		m["network"] = "ws"
		opts := map[string]any{"path": t.Path}
		if t.Host != "" {
			opts["headers"] = map[string]any{"Host": t.Host}
		}
		m["ws-opts"] = opts
	case spec.TransportGRPC:
		m["network"] = "grpc"
		m["grpc-opts"] = map[string]any{"grpc-service-name": t.ServiceName}
	case spec.TransportHTTPUpgrade:
		m["network"] = "ws"
		m["ws-opts"] = map[string]any{"path": t.Path, "v2ray-http-upgrade": true, "headers": map[string]any{"Host": t.Host}}
	case spec.TransportXHTTP:
		m["network"] = "xhttp"
		m["xhttp-opts"] = map[string]any{"path": t.Path, "host": t.Host, "mode": t.Mode}
	}
	return core.Prune(m).(map[string]any)
}

// UserInfo builds the subscription-userinfo header value clients use to show usage.
func UserInfo(up, down, total, expire int64) string {
	return fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", up, down, total, expire)
}
