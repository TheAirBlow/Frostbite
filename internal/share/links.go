package share

import (
	"cmp"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"frostbite/internal/spec"
)

// Link renders an upstream as a share link most clients can import.
func Link(u spec.Upstream) (string, error) {
	if u.RawLink != "" {
		return u.RawLink, nil
	}
	name := url.PathEscape(u.Name)
	hostport := fmt.Sprintf("%s:%d", bracket(u.Address), u.Port)

	switch u.Protocol {
	case spec.ProtoVLESS:
		q := streamQuery(u)
		q.Set("encryption", "none")
		setIf(q, "flow", u.Options.Flow)
		muxQuery(q, u.Options.Mux)
		return fmt.Sprintf("vless://%s@%s?%s#%s", u.UUID, hostport, q.Encode(), name), nil
	case spec.ProtoVMess:
		return vmessLink(u), nil
	case spec.ProtoTrojan:
		q := streamQuery(u)
		muxQuery(q, u.Options.Mux)
		return fmt.Sprintf("trojan://%s@%s?%s#%s", url.QueryEscape(u.Password), hostport, q.Encode(), name), nil
	case spec.ProtoShadowsocks:
		cred := base64.RawURLEncoding.EncodeToString([]byte(u.Options.Method + ":" + u.Password))
		q := url.Values{}
		muxQuery(q, u.Options.Mux)
		return fmt.Sprintf("ss://%s@%s%s#%s", cred, hostport, withQuery(q), name), nil
	case spec.ProtoHysteria2:
		q := url.Values{}
		setIf(q, "sni", u.Security.SNI)
		if u.Security.Insecure {
			q.Set("insecure", "1")
		}
		setIf(q, "ech", u.Security.ECHConfig)
		setIf(q, "obfs", u.Options.Obfs)
		setIf(q, "obfs-password", u.Options.ObfsPass)
		setIf(q, "mport", u.Options.Ports)
		setInt(q, "upmbps", u.Options.UpMbps)
		setInt(q, "downmbps", u.Options.DownMbps)
		return fmt.Sprintf("hysteria2://%s@%s?%s#%s", url.QueryEscape(u.Password), hostport, q.Encode(), name), nil
	case spec.ProtoTUIC:
		q := url.Values{}
		setIf(q, "sni", u.Security.SNI)
		alpn := "h3"
		if len(u.Security.ALPN) > 0 {
			alpn = strings.Join(u.Security.ALPN, ",")
		}
		q.Set("alpn", alpn)
		q.Set("udp_relay_mode", "native")
		setIf(q, "congestion_control", u.Options.CongestCtl)
		if u.Options.ZeroRTT {
			q.Set("zero_rtt_handshake", "true")
		}
		setIf(q, "heartbeat", u.Options.Heartbeat)
		setIf(q, "ech", u.Security.ECHConfig)
		if u.Security.Insecure {
			q.Set("allow_insecure", "1")
			q.Set("insecure", "1")
		}
		return fmt.Sprintf("tuic://%s:%s@%s?%s#%s", u.UUID, url.QueryEscape(u.Password), hostport, q.Encode(), name), nil
	case spec.ProtoAnyTLS:
		q := url.Values{}
		setIf(q, "sni", u.Security.SNI)
		if u.Security.Insecure {
			q.Set("insecure", "1")
		}
		setIf(q, "fp", u.Security.Fingerprint)
		if len(u.Security.ALPN) > 0 {
			q.Set("alpn", strings.Join(u.Security.ALPN, ","))
		}
		setIf(q, "ech", u.Security.ECHConfig)
		fragmentQuery(q, u.Options.Fragment)
		return fmt.Sprintf("anytls://%s@%s?%s#%s", url.QueryEscape(u.Password), hostport, q.Encode(), name), nil
	case spec.ProtoNaive:
		// uot and sni are the parameters Throne and NekoBox read, UDP over TCP is answered by sing-box and the naive daemon
		q := url.Values{"uot": {"1"}}
		setIf(q, "sni", u.Security.SNI)
		fragmentQuery(q, u.Options.Fragment)
		return fmt.Sprintf("naive+https://%s:%s@%s?%s#%s", url.QueryEscape(u.Username), url.QueryEscape(u.Password), hostport, q.Encode(), name), nil
	case spec.ProtoMTProto:
		secret := u.Password
		if u.Options.MTMode == "padded" {
			secret = "dd" + secret
		} else {
			secret = "ee" + secret + hex.EncodeToString([]byte(u.Options.MTDomain))
		}
		q := url.Values{"server": {u.Address}, "port": {strconv.Itoa(u.Port)}, "secret": {secret}}
		return "tg://proxy?" + q.Encode(), nil
	case spec.ProtoTurnable:
		return turnableLink(u)
	case spec.ProtoWireGuard:
		q := url.Values{}
		q.Set("publickey", u.Options.WGPublic)
		q.Set("address", u.Options.WGAddress+"/32")
		setInt(q, "mtu", u.Options.WGMTU)
		setIf(q, "dns", u.Options.WGDNS)
		return fmt.Sprintf("wireguard://%s@%s?%s#%s", url.QueryEscape(u.Password), hostport, q.Encode(), name), nil
	case spec.ProtoSOCKS, spec.ProtoMixed:
		cred := base64.RawURLEncoding.EncodeToString([]byte(u.Username + ":" + u.Password))
		return fmt.Sprintf("socks://%s@%s#%s", cred, hostport, name), nil
	case spec.ProtoHTTP:
		scheme := "http"
		if u.Security.Type == spec.SecurityTLS {
			scheme = "https"
		}
		auth := ""
		if u.Username != "" {
			auth = url.UserPassword(u.Username, u.Password).String() + "@"
		}
		q := url.Values{}
		if scheme == "https" {
			setIf(q, "sni", u.Security.SNI)
			if u.Security.Insecure {
				q.Set("insecure", "1")
			}
		}
		return fmt.Sprintf("%s://%s%s%s#%s", scheme, auth, hostport, withQuery(q), name), nil
	}
	return "", fmt.Errorf("protocol %s has no share link format", u.Protocol)
}

// streamQuery encodes transport and security the way vless and trojan links do.
func streamQuery(u spec.Upstream) url.Values {
	q := url.Values{}
	t, s := u.Transport, u.Security

	typ := t.Type
	if typ == "" {
		typ = spec.TransportTCP
	}
	q.Set("type", typ)
	setIf(q, "path", earlyDataPath(t))
	setIf(q, "host", t.Host)
	setIf(q, "headers", headerList(t))
	setIf(q, "serviceName", t.ServiceName)
	setIf(q, "mode", t.Mode)
	setIf(q, "seed", t.KCPSeed)

	sec := s.Type
	if sec == "" {
		sec = spec.SecurityNone
	}
	q.Set("security", sec)
	setIf(q, "fp", s.Fingerprint)
	if len(s.ALPN) > 0 {
		q.Set("alpn", strings.Join(s.ALPN, ","))
	}
	if s.Insecure {
		q.Set("allowInsecure", "1")
		q.Set("insecure", "1")
	}
	if sec == spec.SecurityTLS || sec == spec.SecurityReality {
		fragmentQuery(q, u.Options.Fragment)
	}
	switch sec {
	case spec.SecurityTLS:
		setIf(q, "sni", s.SNI)
		setIf(q, "ech", s.ECHConfig)
	case spec.SecurityReality:
		if r := s.Reality; r != nil {
			if len(r.ServerNames) > 0 {
				q.Set("sni", r.ServerNames[0])
			}
			q.Set("pbk", r.PublicKey)
			if len(r.ShortIDs) > 0 {
				q.Set("sid", r.ShortIDs[0])
			}
			setIf(q, "spx", r.SpiderX)
		}
		if s.Fingerprint == "" {
			q.Set("fp", "chrome")
		}
	}
	return q
}

// vmessLink renders the base64 json form v2rayN introduced.
func vmessLink(u spec.Upstream) string {
	t, s := u.Transport, u.Security
	net := t.Type
	if net == "" {
		net = spec.TransportTCP
	}
	tls := ""
	if s.Type == spec.SecurityTLS {
		tls = "tls"
	}
	doc := map[string]any{
		"v": "2", "ps": u.Name, "add": u.Address, "port": strconv.Itoa(u.Port), "id": u.UUID, "aid": "0", "scy": "auto",
		"net": net, "type": "none", "host": t.Host, "path": pathOrService(t), "tls": tls, "sni": s.SNI,
		"alpn": strings.Join(s.ALPN, ","), "fp": s.Fingerprint,
	}
	if s.Insecure {
		doc["insecure"] = "1"
	}
	// Throne reads what the v2rayN form has no field for from throneExtra.
	extra := url.Values{}
	setIf(extra, "headers", headerList(t))
	muxQuery(extra, u.Options.Mux)
	if s.Type == spec.SecurityTLS {
		fragmentQuery(extra, u.Options.Fragment)
	}
	if len(extra) > 0 {
		doc["throneExtra"] = extra.Encode()
	}
	raw, _ := json.Marshal(doc)
	return "vmess://" + base64.StdEncoding.EncodeToString(raw)
}

// pathOrService picks the field vmess links share between ws, grpc and kcp.
func pathOrService(t spec.Transport) string {
	switch t.Type {
	case spec.TransportGRPC:
		return t.ServiceName
	case spec.TransportKCP:
		return t.KCPSeed
	}
	return earlyDataPath(t)
}

// earlyDataPath is the websocket path with ?ed= for early data, the form Xray, sing-box clients and Hiddify read.
func earlyDataPath(t spec.Transport) string {
	if t.Type != spec.TransportWS || t.EarlyData <= 0 {
		return t.Path
	}
	path := t.Path
	if path == "" {
		path = "/"
	}
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + "ed=" + strconv.Itoa(t.EarlyData)
}

// headerList writes extra transport headers as name|value|name|value, the form Throne reads. Host has its own key.
func headerList(t spec.Transport) string {
	switch t.Type {
	case spec.TransportWS, spec.TransportHTTPUpgrade, spec.TransportXHTTP:
	default:
		return ""
	}
	names := make([]string, 0, len(t.Headers))
	for k := range t.Headers {
		if !strings.EqualFold(k, "Host") {
			names = append(names, k)
		}
	}
	slices.Sort(names)
	parts := make([]string, 0, 2*len(names))
	for _, k := range names {
		parts = append(parts, k, t.Headers[k])
	}
	return strings.Join(parts, "|")
}

// muxQuery asks for multiplexing in the forms Throne (mux, mux_*) and Hiddify (muxtype, mux*) read. Off writes
// nothing, since Hiddify turns Xray mux on for any mux value.
func muxQuery(q url.Values, m *spec.Mux) {
	if m == nil || !m.Enabled {
		return
	}
	proto := m.Protocol
	if proto == "" {
		proto = "h2mux"
	}
	q.Set("mux", "true")
	q.Set("mux_protocol", proto)
	q.Set("muxtype", proto)
	setInt(q, "mux_max_streams", m.Concurrency)
	setInt(q, "muxsmax", m.Concurrency)
	if m.Padding {
		q.Set("mux_padding", "true")
		q.Set("muxpad", "true")
	}
}

// Fragment defaults, the values Xray documents.
const (
	fragmentPackets  = "tlshello"
	fragmentLength   = "100-200"
	fragmentInterval = "10-20"
)

// fragmentQuery asks for a split TLS hello in the forms Hiddify (fragment) and Throne (tls_fragment) read.
func fragmentQuery(q url.Values, f *spec.Frag) {
	if f == nil || !f.Enabled {
		return
	}
	q.Set("tls_fragment", "true")
	q.Set("fragment", strings.Join([]string{cmp.Or(f.Packets, fragmentPackets), cmp.Or(f.Length, fragmentLength), cmp.Or(f.Interval, fragmentInterval)}, ","))
}

// withQuery is ?query, or nothing for an empty one.
func withQuery(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	return "?" + q.Encode()
}

// setIf adds a query value only when it has one.
func setIf(q url.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}

// setInt adds a positive number to a query.
func setInt(q url.Values, k string, v int) {
	if v > 0 {
		q.Set(k, strconv.Itoa(v))
	}
}

// bracket wraps ipv6 literals so they survive host:port joining.
func bracket(addr string) string {
	if strings.Contains(addr, ":") && !strings.HasPrefix(addr, "[") {
		return "[" + addr + "]"
	}
	return addr
}

// WGQuick renders a WireGuard profile as a wg-quick config file.
func WGQuick(u spec.Upstream, dns string) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\nAddress = %s/32\n", u.Password, u.Options.WGAddress)
	if dns != "" {
		fmt.Fprintf(&b, "DNS = %s\n", dns)
	}
	mtu := u.Options.WGMTU
	if mtu == 0 {
		mtu = 1420
	}
	fmt.Fprintf(&b, "MTU = %d\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:%d\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n", mtu, u.Options.WGPublic, bracket(u.Address), u.Port)
	return b.String()
}
