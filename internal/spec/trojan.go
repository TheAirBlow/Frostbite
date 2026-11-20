package spec

import (
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"
)

// TrojanUDPTimeout is how long, in seconds, a UDP association of the trojan daemon may stay idle when the inbound sets
// no other limit.
const TrojanUDPTimeout = 60

// TJPlain answers to someone speaking plain HTTP to a trojan port.
const (
	TrojanPlainSite     = "site"     // passed on to the site like any other visitor
	TrojanPlainRedirect = "redirect" // sent to the same address over https
	TrojanPlainNginx    = "nginx"    // the page nginx shows for plain HTTP on its TLS port
)

// trojanCurves are the key exchange groups the trojan daemon offers, by every name people tend to use for them.
var trojanCurves = map[string]tls.CurveID{
	"x25519mlkem768": tls.X25519MLKEM768,
	"x25519":         tls.X25519,
	"p-256":          tls.CurveP256, "p256": tls.CurveP256, "prime256v1": tls.CurveP256, "secp256r1": tls.CurveP256,
	"p-384": tls.CurveP384, "p384": tls.CurveP384, "secp384r1": tls.CurveP384,
	"p-521": tls.CurveP521, "p521": tls.CurveP521, "secp521r1": tls.CurveP521,
}

// TrojanCurve looks up a key exchange group by name.
func TrojanCurve(name string) (tls.CurveID, bool) {
	id, ok := trojanCurves[strings.ToLower(strings.TrimSpace(name))]
	return id, ok
}

// TrojanCipher looks up a TLS 1.2 cipher suite by its Go name.
func TrojanCipher(name string) (uint16, bool) {
	name = strings.TrimSpace(name)
	for _, list := range [][]*tls.CipherSuite{tls.CipherSuites(), tls.InsecureCipherSuites()} {
		for _, c := range list {
			if c.Name == name && supportsTLS12(c) {
				return c.ID, true
			}
		}
	}
	return 0, false
}

func supportsTLS12(c *tls.CipherSuite) bool {
	for _, v := range c.SupportedVersions {
		if v == tls.VersionTLS12 {
			return true
		}
	}
	return false
}

// validateTrojan checks the settings of an inbound served by the trojan daemon, which sends everyone who is not a
// trojan user on to a real site.
func (in Inbound) validateTrojan() error {
	o := in.Options
	if in.Security.Type != SecurityTLS {
		return Invalid("security.type", "the trojan daemon always speaks tls")
	}
	if err := hostPort(o.TJDest); err != nil {
		return Invalid("options.trojan_dest", "the site %s", err)
	}
	switch o.TJProxy {
	case "", "v1", "v2":
	default:
		return Invalid("options.trojan_dest_proxy", "the PROXY protocol version must be v1 or v2, or empty for none")
	}
	if o.TJIPHeader != "" && !headerName.MatchString(o.TJIPHeader) {
		return Invalid("options.trojan_ip_header", "%q is not a valid header name", o.TJIPHeader)
	}
	for k := range o.TJHeaders {
		if !headerName.MatchString(k) {
			return Invalid("options.trojan_dest_headers", "%q is not a valid header name", k)
		}
	}
	for name, dest := range o.TJBySNI {
		if name == "" || strings.ContainsAny(name, " /:") {
			return Invalid("options.trojan_sni_dest", "%q is not a server name", name)
		}
		if err := hostPort(dest); err != nil {
			return Invalid("options.trojan_sni_dest", "the site for %s %s", name, err)
		}
	}
	for alpn, dest := range o.TJByALPN {
		if alpn == "" {
			return Invalid("options.trojan_alpn_dest", "an ALPN can't be empty")
		}
		if err := hostPort(dest); err != nil {
			return Invalid("options.trojan_alpn_dest", "the site for %s %s", alpn, err)
		}
	}
	for path, dest := range o.TJByPath {
		if !strings.HasPrefix(path, "/") {
			return Invalid("options.trojan_path_dest", "the path %q must start with /", path)
		}
		if err := hostPort(dest); err != nil {
			return Invalid("options.trojan_path_dest", "the site for %s %s", path, err)
		}
	}
	switch o.TJPlain {
	case "", TrojanPlainSite, TrojanPlainRedirect, TrojanPlainNginx:
	default:
		return Invalid("options.trojan_plain", "plain HTTP visitors can be sent to the site, redirected or shown the nginx page")
	}
	switch o.TJMinTLS {
	case "", "1.2", "1.3":
	default:
		return Invalid("options.trojan_tls_min", "the lowest TLS version must be 1.2 or 1.3")
	}
	for _, c := range o.TJCiphers {
		if _, ok := TrojanCipher(c); !ok {
			return Invalid("options.trojan_ciphers", "%q is not a TLS 1.2 cipher suite", c)
		}
	}
	for _, c := range o.TJCurves {
		if _, ok := TrojanCurve(c); !ok {
			return Invalid("options.trojan_curves", "%q is not a key exchange group", c)
		}
	}
	if o.TJUDPIdle < 0 || o.TJUDPIdle > 3600 {
		return Invalid("options.trojan_udp_timeout", "use 1 to 3600 seconds, or leave it empty")
	}
	return nil
}

// hostPort checks a host:port address and says what is wrong with it.
func hostPort(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return errors.New("address must look like host:port")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return errors.New("port must be 1 to 65535")
	}
	return nil
}
