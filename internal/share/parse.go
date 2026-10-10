package share

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"frostbite/internal/spec"
)

// ParseLink reads a share link back into an upstream, so a pasted link can be used as a chain target.
func ParseLink(raw string) (spec.Upstream, error) {
	raw = strings.TrimSpace(raw)
	scheme, _, ok := strings.Cut(raw, "://")
	if !ok {
		return spec.Upstream{}, fmt.Errorf("not a share link")
	}

	switch strings.ToLower(scheme) {
	case "vmess":
		return parseVMess(raw)
	case "ss":
		return parseSS(raw)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return spec.Upstream{}, fmt.Errorf("bad link: %w", err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return spec.Upstream{}, fmt.Errorf("link has no valid port")
	}
	q := u.Query()
	up := spec.Upstream{Name: u.Fragment, Address: u.Hostname(), Port: port}
	pass, _ := u.User.Password()

	switch strings.ToLower(scheme) {
	case "vless":
		up.Protocol, up.UUID = spec.ProtoVLESS, u.User.Username()
		up.Options.Flow = q.Get("flow")
		readStream(&up, q)
	case "trojan":
		up.Protocol, up.Password = spec.ProtoTrojan, u.User.Username()
		readStream(&up, q)
	case "hysteria2", "hy2":
		up.Protocol, up.Password = spec.ProtoHysteria2, u.User.Username()
		if pass != "" {
			up.Password += ":" + pass
		}
		up.Security = spec.Security{Type: spec.SecurityTLS, SNI: q.Get("sni"), Insecure: q.Get("insecure") == "1"}
		up.Options.Obfs, up.Options.ObfsPass, up.Options.Ports = q.Get("obfs"), q.Get("obfs-password"), q.Get("mport")
	case "tuic":
		up.Protocol, up.UUID, up.Password = spec.ProtoTUIC, u.User.Username(), pass
		up.Security = spec.Security{Type: spec.SecurityTLS, SNI: q.Get("sni"), Insecure: q.Get("allow_insecure") == "1"}
		up.Options.CongestCtl = q.Get("congestion_control")
	case "anytls":
		up.Protocol, up.Password = spec.ProtoAnyTLS, u.User.Username()
		up.Security = spec.Security{Type: spec.SecurityTLS, SNI: q.Get("sni"), Insecure: q.Get("insecure") == "1"}
	case "socks", "socks5":
		up.Protocol = spec.ProtoSOCKS
		up.Username, up.Password = decodeUserinfo(u.User.Username(), pass)
	default:
		return spec.Upstream{}, fmt.Errorf("unsupported link scheme %q", scheme)
	}
	if up.Name == "" {
		up.Name = up.Address
	}
	return up, nil
}

// readStream fills transport and security from a vless or trojan style query.
func readStream(up *spec.Upstream, q url.Values) {
	typ := q.Get("type")
	if typ == "" {
		typ = spec.TransportTCP
	}
	up.Transport = spec.Transport{
		Type: typ, Path: q.Get("path"), Host: q.Get("host"), ServiceName: q.Get("serviceName"), Mode: q.Get("mode"), KCPSeed: q.Get("seed"),
	}
	up.Security = spec.Security{Type: q.Get("security"), SNI: q.Get("sni"), Fingerprint: q.Get("fp"), Insecure: q.Get("allowInsecure") == "1"}
	if a := q.Get("alpn"); a != "" {
		up.Security.ALPN = strings.Split(a, ",")
	}
	if up.Security.Type == "" {
		up.Security.Type = spec.SecurityNone
	}
	if up.Security.Type == spec.SecurityReality {
		up.Security.Reality = &spec.Reality{
			ServerNames: []string{q.Get("sni")}, PublicKey: q.Get("pbk"), ShortIDs: []string{q.Get("sid")}, SpiderX: q.Get("spx"),
		}
	}
}

// parseVMess reads the base64 json vmess form.
func parseVMess(raw string) (spec.Upstream, error) {
	body := strings.TrimPrefix(raw, "vmess://")
	data, err := decodeB64(body)
	if err != nil {
		return spec.Upstream{}, fmt.Errorf("vmess link is not base64: %w", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return spec.Upstream{}, fmt.Errorf("vmess link is not json: %w", err)
	}
	str := func(k string) string { return fmt.Sprint(valueOr(doc[k], "")) }
	port, _ := strconv.Atoi(str("port"))

	up := spec.Upstream{
		Name: str("ps"), Protocol: spec.ProtoVMess, Address: str("add"), Port: port, UUID: str("id"),
		Transport: spec.Transport{Type: str("net"), Host: str("host")},
		Security:  spec.Security{Type: spec.SecurityNone, SNI: str("sni"), Fingerprint: str("fp")},
	}
	if up.Transport.Type == "" {
		up.Transport.Type = spec.TransportTCP
	}
	if up.Transport.Type == spec.TransportGRPC {
		up.Transport.ServiceName = str("path")
	} else {
		up.Transport.Path = str("path")
	}
	if str("tls") == "tls" {
		up.Security.Type = spec.SecurityTLS
	}
	if a := str("alpn"); a != "" {
		up.Security.ALPN = strings.Split(a, ",")
	}
	return up, nil
}

// parseSS reads both SIP002 and the legacy fully-encoded shadowsocks forms.
func parseSS(raw string) (spec.Upstream, error) {
	body := strings.TrimPrefix(raw, "ss://")
	body, frag, _ := strings.Cut(body, "#")
	name, _ := url.PathUnescape(frag)

	if !strings.Contains(body, "@") {
		data, err := decodeB64(body)
		if err != nil {
			return spec.Upstream{}, fmt.Errorf("ss link is not base64: %w", err)
		}
		body = string(data)
	}
	userinfo, hostport, ok := strings.Cut(body, "@")
	if !ok {
		return spec.Upstream{}, fmt.Errorf("ss link has no server")
	}
	hostport, _, _ = strings.Cut(hostport, "?")

	if !strings.Contains(userinfo, ":") {
		data, err := decodeB64(userinfo)
		if err != nil {
			return spec.Upstream{}, fmt.Errorf("ss credentials are not base64: %w", err)
		}
		userinfo = string(data)
	} else if dec, err := url.PathUnescape(userinfo); err == nil {
		userinfo = dec
	}
	method, pass, ok := strings.Cut(userinfo, ":")
	if !ok {
		return spec.Upstream{}, fmt.Errorf("ss credentials need method:password")
	}

	u, err := url.Parse("//" + hostport)
	if err != nil {
		return spec.Upstream{}, err
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return spec.Upstream{}, fmt.Errorf("ss link has no valid port")
	}
	if name == "" {
		name = u.Hostname()
	}
	return spec.Upstream{
		Name: name, Protocol: spec.ProtoShadowsocks, Address: u.Hostname(), Port: port, Password: pass,
		Options: spec.Options{Method: method},
	}, nil
}

// decodeUserinfo reads socks credentials that may be base64 encoded user:pass.
func decodeUserinfo(user, pass string) (string, string) {
	if pass != "" {
		return user, pass
	}
	if data, err := decodeB64(user); err == nil {
		if a, b, ok := strings.Cut(string(data), ":"); ok {
			return a, b
		}
	}
	return user, pass
}

// decodeB64 accepts every base64 flavour share links show up in.
func decodeB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if data, err := enc.DecodeString(s); err == nil {
			return data, nil
		}
	}
	return nil, fmt.Errorf("invalid base64")
}

// valueOr returns v unless it is nil.
func valueOr(v any, def any) any {
	if v == nil {
		return def
	}
	return v
}
