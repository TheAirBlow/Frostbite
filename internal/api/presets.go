package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"frostbite/internal/keys"
	"frostbite/internal/spec"
)

// presetParam is one question a preset asks before it builds an inbound.
type presetParam struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Hint    string `json:"hint,omitempty"`
	Default string `json:"default,omitempty"`
	Kind    string `json:"kind"` // string or number
}

// preset builds a ready to use inbound from a handful of answers.
type preset struct {
	ID          string        `json:"id"`
	Label       string        `json:"label"`
	Description string        `json:"description"`
	Group       string        `json:"group"`
	Cores       []string      `json:"cores"`
	Params      []presetParam `json:"params"`
	build       func(p presetValues, req *inboundRequest) error
}

// presetValues reads the answers given to a preset.
type presetValues map[string]any

// str returns a parameter as a string.
func (p presetValues) str(key, def string) string {
	switch v := p[key].(type) {
	case string:
		if v != "" {
			return v
		}
	case float64:
		return strconv.Itoa(int(v))
	}
	return def
}

// num returns a parameter as an int.
func (p presetValues) num(key string, def int) int {
	switch v := p[key].(type) {
	case float64:
		if v > 0 {
			return int(v)
		}
	case string:
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

var (
	pPort = func(def string) presetParam {
		return presetParam{Key: "port", Label: "Port", Default: def, Kind: "number"}
	}
	pDomain = presetParam{Key: "sni", Label: "Domain (SNI)", Hint: "Defaults to the node address", Kind: "string"}
	pCert   = presetParam{Key: "cert", Label: "Certificate path", Hint: "Path on the node", Default: "/certs/fullchain.pem", Kind: "string"}
	pKey    = presetParam{Key: "key", Label: "Key path", Hint: "Path on the node", Default: "/certs/privkey.pem", Kind: "string"}
	pEmail  = presetParam{Key: "email", Label: "Email for an automatic certificate", Hint: "Fill this to get a free Let's Encrypt certificate. Needs a real domain pointing at the node, and port 80 free there. The paths above are ignored.", Kind: "string"}
	pPath   = presetParam{Key: "path", Label: "Path", Hint: "Leave empty for a random one", Kind: "string"}
	pDest   = presetParam{Key: "dest", Label: "Handshake target", Hint: "A real site that speaks TLS 1.3, as host:port", Default: "www.cloudflare.com:443", Kind: "string"}
)

// bothCores lists the preset targets that work on xray and sing-box alike.
var bothCores = []string{"xray", "singbox"}

// presets is every inbound recipe the panel offers.
var presets = []preset{
	{
		ID: "mtproto-faketls", Label: "Telegram proxy", Group: "Telegram", Cores: []string{"mtproto"},
		Description: "A proxy for Telegram alone. Every user gets their own secret, and probes see the cover site.",
		Params:      []presetParam{pPort("443"), {Key: "domain", Label: "Cover site", Hint: "A real site, as a domain name", Default: "www.cloudflare.com", Kind: "string"}},
		build: func(p presetValues, req *inboundRequest) error {
			req.Protocol, req.Port = spec.ProtoMTProto, int32(p.num("port", 443))
			req.Options = spec.Options{MTMode: "faketls", MTDomain: p.str("domain", "www.cloudflare.com")}
			return nil
		},
	},
	{
		ID: "turnable-vk", Label: "Turnable over VK", Group: "Other", Cores: []string{"turnable"},
		Description: "Hides a tunnel in a public VK call. Leads to one destination, like a WireGuard inbound on this node.",
		Params: []presetParam{
			pPort("56000"),
			{Key: "call", Label: "Call ID", Hint: "The code at the end of a vk.com/call/join/ link", Kind: "string"},
			{Key: "target", Label: "Destination", Hint: "Where the tunnel leads, as ip:port", Default: "127.0.0.1:51820", Kind: "string"},
			{Key: "socket", Label: "Network", Hint: "tcp or udp", Default: "udp", Kind: "string"},
		},
		build: func(p presetValues, req *inboundRequest) error {
			pair, err := keys.Turnable()
			if err != nil {
				return err
			}
			req.Protocol, req.Port = spec.ProtoTurnable, int32(p.num("port", 56000))
			req.Security = spec.Security{Type: spec.SecurityNone}
			req.Options = spec.Options{
				TPlatform: spec.TurnablePlatform, TCallID: p.str("call", ""), TTarget: p.str("target", "127.0.0.1:51820"),
				TSocket: p.str("socket", "udp"), TProto: spec.TurnableProto, TTransport: spec.TurnableTransport,
				TEncryption: spec.TurnableEncryption, TPeers: spec.TurnablePeers, TPrivate: pair.Private, TPublic: pair.Public,
			}
			return nil
		},
	},
	{
		ID: "vless-reality", Label: "VLESS + REALITY", Group: "Recommended", Cores: bothCores,
		Description: "Looks like a visit to a real site. No domain or certificate needed.",
		Params:      []presetParam{pPort("443"), pDest},
		build: func(p presetValues, req *inboundRequest) error {
			sec, err := realitySecurity(p.str("dest", "www.cloudflare.com:443"))
			if err != nil {
				return err
			}
			req.Protocol, req.Port = spec.ProtoVLESS, int32(p.num("port", 443))
			req.Transport = spec.Transport{Type: spec.TransportTCP}
			req.Security = sec
			req.Options = spec.Options{Flow: "xtls-rprx-vision"}
			req.Sniffing = spec.Sniffing{Enabled: true}
			return nil
		},
	},
	{
		ID: "vless-xhttp-reality", Label: "VLESS + XHTTP + REALITY", Group: "Recommended", Cores: []string{"xray"},
		Description: "REALITY over XHTTP, good where plain TCP gets throttled.",
		Params:      []presetParam{pPort("443"), pDest, pPath},
		build: func(p presetValues, req *inboundRequest) error {
			sec, err := realitySecurity(p.str("dest", "www.cloudflare.com:443"))
			if err != nil {
				return err
			}
			req.Protocol, req.Port = spec.ProtoVLESS, int32(p.num("port", 443))
			req.Transport = spec.Transport{Type: spec.TransportXHTTP, Path: pathOrRandom(p), Mode: "auto"}
			req.Security = sec
			req.Sniffing = spec.Sniffing{Enabled: true}
			return nil
		},
	},
	wsTLS("vless-ws-tls", "VLESS + WebSocket + TLS", spec.ProtoVLESS, "Works behind CDNs such as Cloudflare."),
	wsTLS("vmess-ws-tls", "VMess + WebSocket + TLS", spec.ProtoVMess, "Old but widely supported."),
	wsTLS("trojan-ws-tls", "Trojan + WebSocket + TLS", spec.ProtoTrojan, "Trojan behind a CDN."),
	{
		ID: "vless-grpc-tls", Label: "VLESS + gRPC + TLS", Group: "CDN friendly", Cores: bothCores,
		Description: "gRPC transport, accepted by most CDNs.",
		Params:      []presetParam{pPort("443"), pDomain, pCert, pKey, pEmail, {Key: "service", Label: "Service name", Hint: "Leave empty for a random one", Kind: "string"}},
		build: func(p presetValues, req *inboundRequest) error {
			req.Protocol, req.Port = spec.ProtoVLESS, int32(p.num("port", 443))
			req.Transport = spec.Transport{Type: spec.TransportGRPC, ServiceName: p.str("service", randomPath()[1:])}
			req.Security = tlsSecurity(p, "h2")
			req.Sniffing = spec.Sniffing{Enabled: true}
			return nil
		},
	},
	{
		ID: "vless-httpupgrade-tls", Label: "VLESS + HTTPUpgrade + TLS", Group: "CDN friendly", Cores: bothCores,
		Description: "Lighter than WebSocket, same CDN support.",
		Params:      []presetParam{pPort("443"), pDomain, pCert, pKey, pEmail, pPath},
		build: func(p presetValues, req *inboundRequest) error {
			req.Protocol, req.Port = spec.ProtoVLESS, int32(p.num("port", 443))
			req.Transport = spec.Transport{Type: spec.TransportHTTPUpgrade, Path: pathOrRandom(p)}
			req.Security = tlsSecurity(p, "http/1.1")
			req.Sniffing = spec.Sniffing{Enabled: true}
			return nil
		},
	},
	{
		ID: "vless-xhttp-tls", Label: "VLESS + XHTTP + TLS", Group: "CDN friendly", Cores: []string{"xray"},
		Description: "XHTTP with a real certificate, for CDNs that allow it.",
		Params:      []presetParam{pPort("443"), pDomain, pCert, pKey, pEmail, pPath},
		build: func(p presetValues, req *inboundRequest) error {
			req.Protocol, req.Port = spec.ProtoVLESS, int32(p.num("port", 443))
			req.Transport = spec.Transport{Type: spec.TransportXHTTP, Path: pathOrRandom(p), Mode: "auto"}
			req.Security = tlsSecurity(p, "h2")
			req.Sniffing = spec.Sniffing{Enabled: true}
			return nil
		},
	},
	{
		ID: "hysteria2", Label: "Hysteria2", Group: "UDP / QUIC", Cores: []string{"singbox"},
		Description: "Fast over lossy links. Needs a UDP port and a certificate.",
		Params:      []presetParam{pPort("8443"), pDomain, pCert, pKey, pEmail, {Key: "obfs", Label: "Obfuscation password", Hint: "Leave empty to turn salamander off", Kind: "string"}},
		build: func(p presetValues, req *inboundRequest) error {
			req.Protocol, req.Port = spec.ProtoHysteria2, int32(p.num("port", 8443))
			req.Security = tlsSecurity(p, "h3")
			req.Options = spec.Options{Masquerade: "https://www.bing.com"}
			if pw := p.str("obfs", ""); pw != "" {
				req.Options.Obfs, req.Options.ObfsPass = "salamander", pw
			}
			return nil
		},
	},
	{
		ID: "tuic", Label: "TUIC v5", Group: "UDP / QUIC", Cores: []string{"singbox"},
		Description: "QUIC based, low latency.",
		Params:      []presetParam{pPort("8444"), pDomain, pCert, pKey, pEmail},
		build: func(p presetValues, req *inboundRequest) error {
			req.Protocol, req.Port = spec.ProtoTUIC, int32(p.num("port", 8444))
			req.Security = tlsSecurity(p, "h3")
			req.Options = spec.Options{CongestCtl: "bbr", ZeroRTT: true, Heartbeat: "10s"}
			return nil
		},
	},
	{
		ID: "anytls", Label: "AnyTLS", Group: "Other", Cores: []string{"singbox"},
		Description: "TLS with traffic shaping against fingerprinting.",
		Params:      []presetParam{pPort("8445"), pDomain, pCert, pKey, pEmail},
		build: func(p presetValues, req *inboundRequest) error {
			req.Protocol, req.Port = spec.ProtoAnyTLS, int32(p.num("port", 8445))
			req.Security = tlsSecurity(p, "h2,http/1.1")
			return nil
		},
	},
	{
		ID: "shadowsocks-2022", Label: "Shadowsocks 2022", Group: "Other", Cores: bothCores,
		Description: "Modern shadowsocks with one key per user.",
		Params:      []presetParam{pPort("8388")},
		build: func(p presetValues, req *inboundRequest) error {
			method := "2022-blake3-aes-128-gcm"
			key, err := keys.SS2022(method)
			if err != nil {
				return err
			}
			req.Protocol, req.Port = spec.ProtoShadowsocks, int32(p.num("port", 8388))
			req.Options = spec.Options{Method: method, ServerKey: key}
			req.Security = spec.Security{Type: spec.SecurityNone}
			return nil
		},
	},
	{
		ID: "wireguard", Label: "WireGuard", Group: "UDP / QUIC", Cores: []string{"singbox"},
		Description: "Plain WireGuard for apps and routers. Every user gets a key and an address of their own.",
		Params:      []presetParam{pPort("51820"), {Key: "subnet", Label: "Tunnel subnet", Hint: "Users get one address each from it", Default: "10.8.0.0/16", Kind: "string"}, {Key: "dns", Label: "DNS for clients", Default: "1.1.1.1", Kind: "string"}},
		build: func(p presetValues, req *inboundRequest) error {
			pair, err := keys.WireGuard()
			if err != nil {
				return err
			}
			req.Protocol, req.Port = spec.ProtoWireGuard, int32(p.num("port", 51820))
			req.Security = spec.Security{Type: spec.SecurityNone}
			req.Options = spec.Options{WGSubnet: p.str("subnet", "10.8.0.0/16"), WGPrivate: pair.Private, WGPublic: pair.Public, WGMTU: 1420, WGDNS: p.str("dns", "1.1.1.1")}
			req.Sniffing = spec.Sniffing{Enabled: true}
			return nil
		},
	},
	{
		ID: "mixed", Label: "SOCKS / HTTP proxy", Group: "Other", Cores: bothCores,
		Description: "A plain authenticated proxy, handy as a bridge target.",
		Params:      []presetParam{pPort("1080")},
		build: func(p presetValues, req *inboundRequest) error {
			req.Protocol, req.Port = spec.ProtoSOCKS, int32(p.num("port", 1080))
			req.Options = spec.Options{Auth: true, UDP: true}
			req.Security = spec.Security{Type: spec.SecurityNone}
			return nil
		},
	},
}

// wsTLS builds a websocket over TLS preset for the given protocol.
func wsTLS(id, label, protocol, desc string) preset {
	return preset{
		ID: id, Label: label, Group: "CDN friendly", Cores: bothCores, Description: desc,
		Params: []presetParam{pPort("443"), pDomain, pCert, pKey, pEmail, pPath},
		build: func(p presetValues, req *inboundRequest) error {
			req.Protocol, req.Port = protocol, int32(p.num("port", 443))
			req.Transport = spec.Transport{Type: spec.TransportWS, Path: pathOrRandom(p)}
			req.Security = tlsSecurity(p, "http/1.1")
			req.Sniffing = spec.Sniffing{Enabled: true}
			return nil
		},
	}
}

// pathOrRandom reads the path answer or invents one.
func pathOrRandom(p presetValues) string {
	if v := p.str("path", ""); v != "" {
		return v
	}
	return randomPath()
}

// randomPath returns something like /a1b2c3d4.
func randomPath() string {
	h, _ := keys.Hex(4)
	return "/" + h
}

// tlsSecurity builds the tls block shared by the certificate based presets.
func tlsSecurity(p presetValues, alpn string) spec.Security {
	sec := spec.Security{
		Type: spec.SecurityTLS, SNI: p.str("sni", ""), ALPN: splitComma(alpn),
		CertPath: p.str("cert", "/certs/fullchain.pem"), KeyPath: p.str("key", "/certs/privkey.pem"),
	}
	if email := p.str("email", ""); email != "" {
		sec.ACME = &spec.ACME{Domain: sec.SNI, Email: email}
	}
	return sec
}

// splitComma splits a comma list, ignoring blanks.
func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// realitySecurity generates fresh REALITY keys for a handshake target.
func realitySecurity(dest string) (spec.Security, error) {
	host, _, err := net.SplitHostPort(dest)
	if err != nil {
		return spec.Security{}, fmt.Errorf("handshake target must look like host:port")
	}
	pair, err := keys.Reality()
	if err != nil {
		return spec.Security{}, err
	}
	sid, err := keys.ShortID(4)
	if err != nil {
		return spec.Security{}, err
	}
	return spec.Security{
		Type: spec.SecurityReality, Fingerprint: "chrome",
		Reality: &spec.Reality{Dest: dest, ServerNames: []string{host}, PrivateKey: pair.Private, PublicKey: pair.Public, ShortIDs: []string{sid}},
	}, nil
}

// listPresets lists the inbound recipes.
func (s *Server) listPresets(w http.ResponseWriter, r *http.Request) {
	ok(w, presets)
}

// applyPreset fills a request from a preset and the answers in its params.
func (s *Server) applyPreset(ctx context.Context, req *inboundRequest) error {
	i := slices.IndexFunc(presets, func(p preset) bool { return p.ID == req.Preset })
	if i < 0 {
		return errNoPreset(req.Preset)
	}
	pr := presets[i]

	d, err := s.Queries.GetDaemon(ctx, req.DaemonID)
	if err != nil {
		return fmt.Errorf("the daemon does not exist")
	}
	if !slices.Contains(pr.Cores, d.Kind) {
		return fmt.Errorf("%s can't run on a %s daemon", pr.Label, d.Kind)
	}
	node, err := s.Queries.GetNode(ctx, d.NodeID)
	if err != nil {
		return err
	}

	p := presetValues(req.Params)
	if p == nil {
		p = presetValues{}
	}
	if p.str("sni", "") == "" {
		p["sni"] = node.Address
	}
	if err := pr.build(p, req); err != nil {
		return err
	}
	if req.Tag == "" {
		req.Tag, err = s.freeTag(ctx, req.DaemonID, pr.ID, int(req.Port))
		if err != nil {
			return err
		}
	}
	if req.Remark == "" {
		req.Remark = pr.Label
	}
	return nil
}

// freeTag makes a tag nobody on the daemon uses yet.
func (s *Server) freeTag(ctx context.Context, daemonID int64, base string, port int) (string, error) {
	existing, err := s.Queries.ListInboundsByDaemon(ctx, daemonID)
	if err != nil {
		return "", err
	}
	tag := fmt.Sprintf("%s-%d", base, port)
	used := map[string]bool{}
	for _, in := range existing {
		used[in.Tag] = true
	}
	for n := 2; used[tag]; n++ {
		tag = fmt.Sprintf("%s-%d-%d", base, port, n)
	}
	return tag, nil
}
