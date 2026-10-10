package share

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"frostbite/internal/spec"
)

// Link renders an upstream as a share link most clients can import.
func Link(u spec.Upstream) (string, error) {
	name := url.PathEscape(u.Name)
	hostport := fmt.Sprintf("%s:%d", bracket(u.Address), u.Port)

	switch u.Protocol {
	case spec.ProtoVLESS:
		q := streamQuery(u)
		q.Set("encryption", "none")
		setIf(q, "flow", u.Options.Flow)
		return fmt.Sprintf("vless://%s@%s?%s#%s", u.UUID, hostport, q.Encode(), name), nil
	case spec.ProtoVMess:
		return vmessLink(u), nil
	case spec.ProtoTrojan:
		return fmt.Sprintf("trojan://%s@%s?%s#%s", url.QueryEscape(u.Password), hostport, streamQuery(u).Encode(), name), nil
	case spec.ProtoShadowsocks:
		cred := base64.RawURLEncoding.EncodeToString([]byte(u.Options.Method + ":" + u.Password))
		return fmt.Sprintf("ss://%s@%s#%s", cred, hostport, name), nil
	case spec.ProtoHysteria2:
		q := url.Values{}
		setIf(q, "sni", u.Security.SNI)
		if u.Security.Insecure {
			q.Set("insecure", "1")
		}
		setIf(q, "obfs", u.Options.Obfs)
		setIf(q, "obfs-password", u.Options.ObfsPass)
		setIf(q, "mport", u.Options.Ports)
		return fmt.Sprintf("hysteria2://%s@%s?%s#%s", url.QueryEscape(u.Password), hostport, q.Encode(), name), nil
	case spec.ProtoTUIC:
		q := url.Values{}
		setIf(q, "sni", u.Security.SNI)
		q.Set("alpn", "h3")
		q.Set("udp_relay_mode", "native")
		setIf(q, "congestion_control", u.Options.CongestCtl)
		if u.Security.Insecure {
			q.Set("allow_insecure", "1")
		}
		return fmt.Sprintf("tuic://%s:%s@%s?%s#%s", u.UUID, url.QueryEscape(u.Password), hostport, q.Encode(), name), nil
	case spec.ProtoAnyTLS:
		q := url.Values{}
		setIf(q, "sni", u.Security.SNI)
		if u.Security.Insecure {
			q.Set("insecure", "1")
		}
		return fmt.Sprintf("anytls://%s@%s?%s#%s", url.QueryEscape(u.Password), hostport, q.Encode(), name), nil
	case spec.ProtoNaive:
		return fmt.Sprintf("naive+https://%s:%s@%s#%s", url.QueryEscape(u.Username), url.QueryEscape(u.Password), hostport, name), nil
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
		if u.Options.WGMTU > 0 {
			q.Set("mtu", strconv.Itoa(u.Options.WGMTU))
		}
		return fmt.Sprintf("wireguard://%s@%s?%s#%s", url.QueryEscape(u.Password), hostport, q.Encode(), name), nil
	case spec.ProtoSOCKS, spec.ProtoMixed:
		cred := base64.RawURLEncoding.EncodeToString([]byte(u.Username + ":" + u.Password))
		return fmt.Sprintf("socks://%s@%s#%s", cred, hostport, name), nil
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
	setIf(q, "path", t.Path)
	setIf(q, "host", t.Host)
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
	raw, _ := json.Marshal(doc)
	return "vmess://" + base64.StdEncoding.EncodeToString(raw)
}

// pathOrService picks the field vmess links share between ws and grpc.
func pathOrService(t spec.Transport) string {
	if t.Type == spec.TransportGRPC {
		return t.ServiceName
	}
	return t.Path
}

// setIf adds a query value only when it has one.
func setIf(q url.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
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
