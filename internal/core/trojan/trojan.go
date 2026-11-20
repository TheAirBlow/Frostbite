// Package trojan renders the config of the trojan daemon, a native trojan server where everyone who is not a trojan
// user is sent on to a real site.
package trojan

import (
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strconv"

	"frostbite/internal/core"
	"frostbite/internal/spec"
)

func init() {
	core.Register(core.Descriptor{
		Kind:        "trojan",
		DisplayName: "Trojan",
		Caps: core.Capabilities{
			Protocols:  []string{spec.ProtoTrojan},
			Transports: []string{spec.TransportTCP},
			Securities: []string{spec.SecurityTLS},
			Outbounds:  []string{spec.OutDirect, spec.OutBlock},
			HotUsers:   true,
		},
		Render: Render,
	})
}

// Config is what the trojan daemon runs. Users are not part of it, so they change without touching a listener.
type Config struct {
	LogLevel  string     `json:"log_level"`
	DNS       DNS        `json:"dns"`
	Inbounds  []Inbound  `json:"inbounds"`
	Outbounds []Outbound `json:"outbounds"`
	Rules     []Rule     `json:"rules"`
	Final     string     `json:"final"`
}

// DNS is the resolver used for destinations given by name.
type DNS struct {
	Servers  []string `json:"servers,omitempty"` // ip or ip:port, the system resolver when empty
	Strategy string   `json:"strategy,omitempty"`
}

// Inbound is one listening port.
type Inbound struct {
	Tag         string `json:"tag"`
	Listen      string `json:"listen"` // host:port
	AcceptProxy bool   `json:"accept_proxy,omitempty"`
	TLS         TLS    `json:"tls"`
	TCP         TCP    `json:"tcp"`
	Site        Site   `json:"site"`
	Plain       string `json:"plain,omitempty"`       // see spec.TrojanPlain*
	UDPTimeout  int    `json:"udp_timeout"`           // seconds
	Sniff       *Sniff `json:"sniff,omitempty"`       // read the first bytes of a tunnel for a server name
	Padding     bool   `json:"mux_padding,omitempty"` // sing-mux clients must pad
}

// TLS is the server side of the handshake.
type TLS struct {
	Cert      string   `json:"cert"`
	Key       string   `json:"key"`
	ALPN      []string `json:"alpn"`
	MinTLS    string   `json:"min_version,omitempty"`
	Ciphers   []string `json:"ciphers,omitempty"`
	Curves    []string `json:"curves,omitempty"`
	NoTickets bool     `json:"no_tickets,omitempty"`
	ECHKey    string   `json:"ech_key,omitempty"`
}

// TCP holds socket options of the listener.
type TCP struct {
	NoDelay   bool `json:"no_delay"`
	KeepAlive bool `json:"keep_alive"`
	ReusePort bool `json:"reuse_port,omitempty"`
	FastOpen  bool `json:"fast_open,omitempty"`
}

// Site is where everyone who is not a trojan user goes once TLS is off.
type Site struct {
	Dest     string            `json:"dest"`
	TLS      bool              `json:"tls,omitempty"`
	SNI      string            `json:"sni,omitempty"` // empty passes the visitor's server name on
	Insecure bool              `json:"insecure,omitempty"`
	Proxy    int               `json:"proxy,omitempty"`     // PROXY protocol version, 0 for none
	IPHeader string            `json:"ip_header,omitempty"` // set, the daemon reads HTTP and adds this header
	Headers  map[string]string `json:"headers,omitempty"`
	BySNI    map[string]string `json:"by_sni,omitempty"`
	ByALPN   map[string]string `json:"by_alpn,omitempty"`
	ByPath   map[string]string `json:"by_path,omitempty"`
}

// HTTP reports whether the site is reached by reading the visitor's requests rather than passing bytes on.
func (s Site) HTTP() bool { return s.IPHeader != "" || len(s.Headers) > 0 }

// Sniff is protocol sniffing on tunnels.
type Sniff struct {
	RouteOnly    bool `json:"route_only,omitempty"`    // the name is only used to pick a rule
	DestOverride bool `json:"dest_override,omitempty"` // dial the sniffed name instead of the address
}

// Outbound is a way out. Only direct and block exist here.
type Outbound struct {
	Tag       string `json:"tag"`
	Kind      string `json:"kind"`
	Interface string `json:"interface,omitempty"`
	Strategy  string `json:"strategy,omitempty"`
}

// Rule sends matching destinations to an outbound, first match wins.
type Rule struct {
	Inbounds     []string `json:"inbounds,omitempty"`
	Users        []string `json:"users,omitempty"`
	Domain       []string `json:"domain,omitempty"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	DomainKw     []string `json:"domain_keyword,omitempty"`
	IPCIDR       []string `json:"ip_cidr,omitempty"`
	Port         []string `json:"port,omitempty"`
	Network      string   `json:"network,omitempty"`
	Outbound     string   `json:"outbound"`
}

// Render builds the config for d.
func Render(d spec.Daemon) ([]byte, error) {
	cfg := Config{
		LogLevel: logLevel(d.Log.Level),
		DNS:      DNS{Servers: plainServers(d.DNS.Servers), Strategy: d.DNS.Strategy},
		Inbounds: []Inbound{}, Outbounds: []Outbound{}, Rules: []Rule{},
		Final: d.Final,
	}
	kinds := map[string]string{}
	for _, o := range d.Outbounds {
		if o.Kind != spec.OutDirect && o.Kind != spec.OutBlock {
			continue
		}
		kinds[o.Tag] = o.Kind
		cfg.Outbounds = append(cfg.Outbounds, Outbound{Tag: o.Tag, Kind: o.Kind, Interface: o.Interface, Strategy: o.Strategy})
	}
	if cfg.Final == "" {
		cfg.Final = spec.OutDirect
	}
	if _, ok := kinds[cfg.Final]; !ok {
		if cfg.Final != spec.OutDirect {
			return nil, fmt.Errorf("final outbound %q is not direct or block, which is all the trojan daemon can use", cfg.Final)
		}
		cfg.Outbounds = append(cfg.Outbounds, Outbound{Tag: spec.OutDirect, Kind: spec.OutDirect})
	}
	for _, r := range d.Rules {
		if _, ok := kinds[r.Outbound]; !ok {
			continue
		}
		// geo lists and sniffed protocols need data this daemon does not carry, so such rules are left out
		if len(r.GeoSite)+len(r.GeoIP)+len(r.Protocol) > 0 {
			continue
		}
		cfg.Rules = append(cfg.Rules, Rule{
			Inbounds: r.InboundTags, Users: r.Users, Domain: r.Domain, DomainSuffix: r.DomainSuffix, DomainKw: r.DomainKw,
			IPCIDR: r.IPCIDR, Port: r.Port, Network: r.Network, Outbound: r.Outbound,
		})
	}

	for _, in := range d.Inbounds {
		if in.Protocol != spec.ProtoTrojan {
			continue
		}
		ib, err := inbound(in)
		if err != nil {
			return nil, fmt.Errorf("inbound %s: %w", in.Tag, err)
		}
		cfg.Inbounds = append(cfg.Inbounds, ib)
	}

	m, err := toMap(cfg)
	if err != nil {
		return nil, err
	}
	for i, in := range trojanInbounds(d) {
		if err := core.ApplyPatch(m["inbounds"].([]any)[i].(map[string]any), in.RawPatch); err != nil {
			return nil, fmt.Errorf("inbound %s: %w", in.Tag, err)
		}
	}
	if err := core.ApplyPatch(m, d.RawPatch); err != nil {
		return nil, err
	}
	return json.MarshalIndent(m, "", "  ")
}

// trojanInbounds lists the inbounds this daemon serves, in config order.
func trojanInbounds(d spec.Daemon) []spec.Inbound {
	var out []spec.Inbound
	for _, in := range d.Inbounds {
		if in.Protocol == spec.ProtoTrojan {
			out = append(out, in)
		}
	}
	return out
}

// toMap turns the config into the generic form patches apply to.
func toMap(cfg Config) (map[string]any, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, json.Unmarshal(raw, &m)
}

// inbound renders one inbound.
func inbound(in spec.Inbound) (Inbound, error) {
	if in.Security.CertPath == "" || in.Security.KeyPath == "" {
		return Inbound{}, fmt.Errorf("no certificate to serve")
	}
	o := in.Options
	site := Site{
		Dest: o.TJDest, TLS: o.TJTLS, SNI: o.TJSNI, Insecure: o.TJSkip, Proxy: proxyVersion(o.TJProxy),
		IPHeader: o.TJIPHeader, Headers: o.TJHeaders, BySNI: o.TJBySNI, ByALPN: o.TJByALPN, ByPath: o.TJByPath,
	}
	alpn := slices.Clone(in.Security.ALPN)
	if len(alpn) == 0 {
		// raw bytes can only reach the site in a protocol it speaks, and HTTP/1.1 is what upstream trojan offers
		alpn = []string{"http/1.1"}
		if site.HTTP() {
			alpn = []string{"h2", "http/1.1"}
		}
	}
	timeout := o.TJUDPIdle
	if timeout <= 0 {
		timeout = spec.TrojanUDPTimeout
	}
	ib := Inbound{
		Tag:         in.Tag,
		Listen:      net.JoinHostPort(in.Listen, strconv.Itoa(in.Port)),
		AcceptProxy: o.AcceptProxy,
		TLS: TLS{
			Cert: in.Security.CertPath, Key: in.Security.KeyPath, ALPN: alpn, MinTLS: o.TJMinTLS,
			Ciphers: o.TJCiphers, Curves: o.TJCurves, NoTickets: o.TJNoTicket, ECHKey: in.Security.ECHKey,
		},
		TCP:        TCP{NoDelay: !o.TJNagle, KeepAlive: !o.TJNoAlive, ReusePort: o.TJReuse, FastOpen: o.TJFastOpen},
		Site:       site,
		Plain:      o.TJPlain,
		UDPTimeout: timeout,
		Padding:    o.Mux != nil && o.Mux.Enabled && o.Mux.Padding,
	}
	if in.Sniffing.Enabled {
		ib.Sniff = &Sniff{RouteOnly: in.Sniffing.RouteOnly, DestOverride: in.Sniffing.DestOverride}
	}
	return ib, nil
}

// proxyVersion turns v1 or v2 into a version number.
func proxyVersion(v string) int {
	switch v {
	case "v1":
		return 1
	case "v2":
		return 2
	}
	return 0
}

// plainServers keeps the resolvers given as an address, the only kind this daemon asks.
func plainServers(servers []string) []string {
	var out []string
	for _, s := range servers {
		if net.ParseIP(s) != nil {
			out = append(out, net.JoinHostPort(s, "53"))
		} else if host, _, err := net.SplitHostPort(s); err == nil && net.ParseIP(host) != nil {
			out = append(out, s)
		}
	}
	return out
}

// logLevel maps a panel log level to the daemon's.
func logLevel(l string) string {
	switch l {
	case "debug", "warning", "error", "none":
		return l
	}
	return "info"
}
