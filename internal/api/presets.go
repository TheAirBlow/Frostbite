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
	// Required parameters have to be filled in: there is nothing sensible to fall back on.
	Required bool `json:"required,omitempty"`
	// Options turns the field into a choice, Labels says how each option reads.
	Options []string `json:"options,omitempty"`
	Labels  []string `json:"labels,omitempty"`
	// Show limits the field to when another answer has one of the listed values.
	Show map[string][]string `json:"show,omitempty"`
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
	pDomain     = presetParam{Key: "sni", Label: "Server name (SNI)", Hint: "The name clients ask for. Empty uses the node address.", Kind: "string"}
	pCertSource = presetParam{
		Key: "cert_source", Label: "Certificate", Default: certExisting, Kind: "string",
		Hint:    "An existing one is found in Caddy's or certbot's storage on the node and renewals are picked up on their own.",
		Options: []string{certExisting, certACME, certFiles, certSelf},
		Labels:  []string{"Use an existing one (Caddy, certbot)", "Get one from Let's Encrypt", "Files on the node", "Self-signed"},
	}
	pCertDomain = presetParam{Key: "cert_domain", Label: "Certificate for", Hint: "The name on the certificate, such as *.example.com. Empty uses the server name.", Kind: "string", Show: map[string][]string{"cert_source": {certExisting, certACME}}}
	pEmail      = presetParam{Key: "email", Label: "Email", Hint: "Optional. Let's Encrypt writes here before a certificate expires. Needs the name pointing at the node and port 80 free.", Kind: "string", Show: map[string][]string{"cert_source": {certACME}}}
	pCert       = presetParam{Key: "cert", Label: "Certificate path", Hint: "Path on the node", Kind: "string", Show: map[string][]string{"cert_source": {certFiles}}}
	pKey        = presetParam{Key: "key", Label: "Key path", Hint: "Path on the node", Kind: "string", Show: map[string][]string{"cert_source": {certFiles}}}
	pPath       = presetParam{Key: "path", Label: "Path", Hint: "Leave empty for a random one", Kind: "string"}
	pDest       = presetParam{Key: "dest", Label: "Handshake target", Hint: "Where the server connects to borrow the handshake, as host:port. A real site that speaks TLS 1.3 and h2, or an IP address when you give the server names below.", Default: "www.cloudflare.com:443", Kind: "string"}
	pNames      = presetParam{Key: "server_names", Label: "Server names (SNI)", Hint: "The names clients send, comma separated. Empty uses the host of the target. Needed when the target is an IP address, such as a site behind a CDN.", Kind: "string"}
)

// Where a certificate based preset gets its certificate.
const (
	certExisting = "existing"
	certACME     = "acme"
	certFiles    = "files"
	certSelf     = "self"
)

// tlsParams are the questions every certificate based preset asks, after the port.
var tlsParams = []presetParam{pDomain, pCertSource, pCertDomain, pEmail, pCert, pKey}

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
		ID: "naive-site", Label: "NaiveProxy with a real site", Group: "Other", Cores: []string{"caddy"},
		Description: "A NaiveProxy server that also acts as the front of a real website. Anyone who is not a proxy user, or fails to log in, is sent on to that site.",
		Params: append(append([]presetParam{pPort("443")}, tlsParams...),
			presetParam{Key: "site", Label: "Site address", Hint: "Where everyone else is sent, as host:port. Usually your web server.", Default: "127.0.0.1:8443", Kind: "string"},
			presetParam{Key: "site_tls", Label: "Site uses HTTPS", Default: "true", Kind: "string", Options: []string{"true", "false"}, Labels: []string{"Yes", "No"}},
			presetParam{Key: "site_proxy", Label: "PROXY protocol to the site", Hint: "Tells the site the visitor's real address, if it accepts the PROXY protocol from this node", Default: "none", Kind: "string", Options: []string{"none", "v1", "v2"}},
		),
		build: func(p presetValues, req *inboundRequest) error {
			req.Protocol, req.Port = spec.ProtoNaive, int32(p.num("port", 443))
			req.Security = tlsSecurity(p, "h2,http/1.1")
			proxy := p.str("site_proxy", "none")
			if proxy == "none" {
				proxy = ""
			}
			req.Options = spec.Options{NaiveDest: p.str("site", "127.0.0.1:8443"), NaiveTLS: p.str("site_tls", "true") == "true", NaiveProxy: proxy}
			return nil
		},
	},
	{
		ID: "turnable-vk", Label: "Turnable over VK", Group: "Other", Cores: []string{"turnable"},
		Description: "Hides a tunnel in a public VK call and leads it to a destination on this node, like a WireGuard inbound. More destinations can be added afterwards.",
		Params: []presetParam{
			pPort("56000"),
			{Key: "call", Label: "Call ID", Hint: "The code at the end of a vk.com/call/join/ link", Kind: "string", Required: true},
			{Key: "target", Label: "Destination", Hint: "Where the tunnel leads, as ip:port", Default: "127.0.0.1:51820", Kind: "string"},
			{Key: "socket", Label: "Network", Hint: "What the destination speaks", Default: "udp", Kind: "string", Options: []string{"udp", "tcp"}},
		},
		build: func(p presetValues, req *inboundRequest) error {
			pair, err := keys.Turnable()
			if err != nil {
				return err
			}
			req.Protocol, req.Port = spec.ProtoTurnable, int32(p.num("port", 56000))
			req.Security = spec.Security{Type: spec.SecurityNone}
			req.Options = spec.Options{
				TPlatform: spec.TurnablePlatform, TCallID: p.str("call", ""), TProto: spec.TurnableProto,
				TRoutes: []spec.TurnableRouteSpec{{
					ID: spec.TurnableRoute, Target: p.str("target", "127.0.0.1:51820"), Socket: p.str("socket", "udp"),
					Transport: spec.TurnableTransport, Encryption: spec.TurnableEncryption,
				}},
				TPeers: spec.TurnablePeers, TPrivate: pair.Private, TPublic: pair.Public,
			}
			return nil
		},
	},
	{
		ID: "vless-reality", Label: "VLESS + REALITY", Group: "Recommended", Cores: bothCores,
		Description: "Looks like a visit to a real site. No domain or certificate needed.",
		Params:      []presetParam{pPort("443"), pDest, pNames},
		build: func(p presetValues, req *inboundRequest) error {
			sec, err := realitySecurity(p.str("dest", "www.cloudflare.com:443"), p.str("server_names", ""))
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
		Params:      []presetParam{pPort("443"), pDest, pNames, pPath},
		build: func(p presetValues, req *inboundRequest) error {
			sec, err := realitySecurity(p.str("dest", "www.cloudflare.com:443"), p.str("server_names", ""))
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
		Params:      append(append([]presetParam{pPort("443")}, tlsParams...), presetParam{Key: "service", Label: "Service name", Hint: "Leave empty for a random one", Kind: "string"}),
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
		Params:      append(append([]presetParam{pPort("443")}, tlsParams...), pPath),
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
		Params:      append(append([]presetParam{pPort("443")}, tlsParams...), pPath),
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
		Params:      append(append([]presetParam{pPort("8443")}, tlsParams...), presetParam{Key: "obfs", Label: "Obfuscation password", Hint: "Leave empty to turn salamander off", Kind: "string"}),
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
		Params:      append([]presetParam{pPort("8444")}, tlsParams...),
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
		Params:      append([]presetParam{pPort("8445")}, tlsParams...),
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
		Params: append(append([]presetParam{pPort("443")}, tlsParams...), pPath),
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
	sec := spec.Security{Type: spec.SecurityTLS, SNI: p.str("sni", ""), ALPN: splitComma(alpn)}
	domain := p.str("cert_domain", sec.SNI)
	switch p.str("cert_source", certExisting) {
	case certExisting:
		sec.Existing = &spec.Existing{Domain: domain}
	case certACME:
		sec.ACME = &spec.ACME{Domain: domain, Email: p.str("email", "")}
	case certFiles:
		sec.CertPath, sec.KeyPath = p.str("cert", ""), p.str("key", "")
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
func realitySecurity(dest, names string) (spec.Security, error) {
	host, _, err := net.SplitHostPort(dest)
	if err != nil {
		return spec.Security{}, spec.Invalid("params.dest", "the handshake target must look like host:port")
	}
	serverNames := []string{host}
	if fields := strings.FieldsFunc(names, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }); len(fields) > 0 {
		serverNames = fields
	} else if net.ParseIP(host) != nil {
		return spec.Security{}, spec.Invalid("params.server_names", "the target is an IP address, so name the site clients should ask for")
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
		Reality: &spec.Reality{Dest: dest, ServerNames: serverNames, PrivateKey: pair.Private, PublicKey: pair.Public, ShortIDs: []string{sid}},
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
