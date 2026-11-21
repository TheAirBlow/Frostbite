// Package spec is the core-agnostic description of what a daemon should run.
package spec

import (
	"encoding/json"
	"strings"
)

// Protocols an inbound or upstream can speak.
const (
	ProtoVLESS       = "vless"
	ProtoVMess       = "vmess"
	ProtoTrojan      = "trojan"
	ProtoShadowsocks = "shadowsocks"
	ProtoHysteria2   = "hysteria2"
	ProtoTUIC        = "tuic"
	ProtoAnyTLS      = "anytls"
	ProtoNaive       = "naive"
	ProtoShadowTLS   = "shadowtls"
	ProtoSOCKS       = "socks"
	ProtoHTTP        = "http"
	ProtoMixed       = "mixed"
	ProtoForward     = "forward"
	ProtoWireGuard   = "wireguard"
	ProtoMTProto     = "mtproto"
	ProtoTurnable    = "turnable"
)

// Transport types.
const (
	TransportTCP         = "tcp"
	TransportWS          = "ws"
	TransportGRPC        = "grpc"
	TransportHTTPUpgrade = "httpupgrade"
	TransportXHTTP       = "xhttp"
	TransportKCP         = "kcp"
	TransportQUIC        = "quic"
)

// Security types.
const (
	SecurityNone    = "none"
	SecurityTLS     = "tls"
	SecurityReality = "reality"
)

// Daemon is the full desired state of one daemon.
type Daemon struct {
	Kind      string          `json:"kind"`
	Revision  int64           `json:"revision"`
	Log       Log             `json:"log"`
	DNS       DNS             `json:"dns"`
	Inbounds  []Inbound       `json:"inbounds"`
	Outbounds []Outbound      `json:"outbounds"`
	Rules     []Rule          `json:"rules"`
	Final     string          `json:"final"` // outbound tag used when no rule matches
	Edge      *Edge           `json:"edge,omitempty"`
	RawPatch  json.RawMessage `json:"raw_patch,omitempty"`
}

// Edge describes a daemon that shares public ports between other daemons by looking at the TLS hello.
type Edge struct {
	Listen  []string    `json:"listen"`  // addresses to accept on, such as :443
	Routes  []EdgeRoute `json:"routes"`  // first match wins
	Default string      `json:"default"` // where unmatched traffic goes, empty drops it
}

// EdgeRoute sends connections for some server names to a local inbound.
type EdgeRoute struct {
	Name   string   `json:"name"`
	SNI    []string `json:"sni"`  // exact names or *.example.com
	ALPN   []string `json:"alpn"` // empty matches any
	Target string   `json:"target"`
	Proxy  bool     `json:"proxy"` // send a PROXY protocol header so the inbound sees the real client
}

// Log sets core log verbosity.
type Log struct {
	Level string `json:"level" ui:"label=Log level,options=debug|info|warning|error|none"`
}

// DNS is the resolver the core uses for its own lookups.
type DNS struct {
	Servers  []string `json:"servers" ui:"label=DNS servers,hint=Plain IPs, https:// or tls:// URLs"`
	Strategy string   `json:"strategy" ui:"label=Strategy,options=prefer_ipv4|prefer_ipv6|ipv4_only|ipv6_only,advanced"`
}

// User is one account on one inbound.
type User struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"` // stable stats label, never shown to clients
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
	Flow     string `json:"flow,omitempty"`
}

// Inbound is one listening endpoint.
type Inbound struct {
	Tag       string          `json:"tag"`
	Protocol  string          `json:"protocol"`
	Listen    string          `json:"listen"`
	Port      int             `json:"port"`
	Transport Transport       `json:"transport"`
	Security  Security        `json:"security"`
	Options   Options         `json:"options"`
	Sniffing  Sniffing        `json:"sniffing"`
	Forward   *Forward        `json:"forward,omitempty"`
	Users     []User          `json:"users"`
	RawPatch  json.RawMessage `json:"raw_patch,omitempty"`
}

// Forward makes an inbound blindly relay everything to another address.
type Forward struct {
	Address string `json:"address" ui:"label=Target address"`
	Port    int    `json:"port" ui:"label=Target port"`
	Network string `json:"network" ui:"label=Network,options=tcp|udp|tcp,udp"`
}

// Sniffing controls protocol sniffing on an inbound.
type Sniffing struct {
	Enabled      bool `json:"enabled" ui:"label=Sniff traffic"`
	RouteOnly    bool `json:"route_only" ui:"label=Route only,hint=The sniffed name only picks the route. The connection still goes to the address the client asked for.,show=core:xray|trojan,advanced"`
	DestOverride bool `json:"dest_override" ui:"label=Override destination,hint=Connect to the sniffed name instead of the address the client asked for.,show=core:trojan,advanced"`
}

// Transport describes the stream layer under the proxy protocol.
type Transport struct {
	Type        string            `json:"type" ui:"label=Transport,options=tcp|ws|grpc|httpupgrade|xhttp|kcp"`
	Path        string            `json:"path,omitempty" ui:"label=Path,show=type:ws|httpupgrade|xhttp"`
	Host        string            `json:"host,omitempty" ui:"label=Host header,show=type:ws|httpupgrade|xhttp,advanced"`
	ServiceName string            `json:"service_name,omitempty" ui:"label=gRPC service name,show=type:grpc"`
	Mode        string            `json:"mode,omitempty" ui:"label=XHTTP mode,options=auto|packet-up|stream-up|stream-one,show=type:xhttp,advanced"`
	Headers     map[string]string `json:"headers,omitempty" ui:"label=Extra headers,show=type:ws|httpupgrade|xhttp,advanced"`
	EarlyData   int               `json:"early_data,omitempty" ui:"label=Max early data,show=type:ws,advanced"`
	KCPSeed     string            `json:"kcp_seed,omitempty" ui:"label=mKCP seed,show=type:kcp,advanced"`
}

// Security describes the TLS layer. Server-only fields never leave the panel in client output.
type Security struct {
	Type        string    `json:"type" ui:"label=Security,options=none|tls|reality"`
	SNI         string    `json:"sni,omitempty" ui:"label=SNI,hint=The name clients ask for. Empty uses the address they connect to.,show=type:tls"`
	ALPN        []string  `json:"alpn,omitempty" ui:"label=ALPN,show=type:tls|reality,advanced"`
	Fingerprint string    `json:"fingerprint,omitempty" ui:"label=uTLS fingerprint,options=|chrome|firefox|safari|ios|android|edge|random,show=type:tls|reality,advanced"`
	Insecure    bool      `json:"insecure,omitempty" ui:"label=Allow insecure,hint=Clients skip the certificate check. Only for self-signed certificates.,show=type:tls,advanced"`
	CertPath    string    `json:"cert_path,omitempty" ui:"label=Certificate path,hint=Path on the node,show=type:tls"`
	KeyPath     string    `json:"key_path,omitempty" ui:"label=Key path,hint=Path on the node,show=type:tls"`
	ECHKey      string    `json:"ech_key,omitempty" ui:"label=ECH key,show=type:tls,advanced"`
	ECHConfig   string    `json:"ech_config,omitempty" ui:"label=ECH config,show=type:tls,advanced"`
	Reality     *Reality  `json:"reality,omitempty"`
	ACME        *ACME     `json:"acme,omitempty"`
	Existing    *Existing `json:"existing,omitempty"`
}

// UnmarshalJSON also accepts the older "caddy" key for an existing certificate.
func (s *Security) UnmarshalJSON(b []byte) error {
	type plain Security
	var v struct {
		plain
		Caddy *Existing `json:"caddy,omitempty"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*s = Security(v.plain)
	if s.Existing == nil {
		s.Existing = v.Caddy
	}
	return nil
}

// ACMEDir is where daemons keep certificates they obtained. An agent with another data directory maps it.
const ACMEDir = "/data/acme"

// ACME asks the daemon to get and renew a Let's Encrypt certificate for a domain on its own.
type ACME struct {
	Domain string `json:"domain"`
	Email  string `json:"email,omitempty"`
}

// Paths returns where the certificate and key live under dir.
func (a ACME) Paths(dir string) (cert, key string) {
	return dir + "/" + a.Domain + "/fullchain.pem", dir + "/" + a.Domain + "/privkey.pem"
}

// ExistingDirs are where daemons search for certificates another tool keeps when the inbound names no folder:
// Caddy's data folder and certbot's config folder, as mounted into the container or on a native install.
var ExistingDirs = []string{"/caddy", "/letsencrypt", "/etc/letsencrypt", "/var/lib/caddy/.local/share/caddy"}

// Existing reuses a certificate another tool on the node already keeps, such as Caddy or certbot.
type Existing struct {
	Domain string `json:"domain"`        // the name on the certificate, *.example.com for a wildcard
	Dir    string `json:"dir,omitempty"` // a folder to search instead of ExistingDirs
}

// ExistingCopyDir is where daemons keep their own copy of an existing certificate, so the core reads a stable path.
const ExistingCopyDir = "/data/existing-certs"

// Paths returns where the daemon's copy of the certificate and key live under dir.
func (e Existing) Paths(dir string) (cert, key string) {
	name := e.Domain
	if rest, ok := strings.CutPrefix(name, "*."); ok {
		name = "wildcard_." + rest
	}
	return dir + "/" + name + "/fullchain.pem", dir + "/" + name + "/privkey.pem"
}

// Reality holds REALITY handshake settings.
type Reality struct {
	Dest        string   `json:"dest" ui:"label=Handshake target,hint=host:port of a real TLS 1.3 site"`
	ServerNames []string `json:"server_names" ui:"label=Server names"`
	PrivateKey  string   `json:"private_key,omitempty"`
	PublicKey   string   `json:"public_key,omitempty"`
	ShortIDs    []string `json:"short_ids" ui:"label=Short IDs"`
	SpiderX     string   `json:"spider_x,omitempty" ui:"label=Spider X,advanced"`
	XVer        int      `json:"xver,omitempty"` // send a PROXY protocol header of this version to the target, 0 for none
}

// Options are protocol specific knobs, each one only used by the protocols that know it.
type Options struct {
	Flow        string              `json:"flow,omitempty" ui:"label=Flow,options=|xtls-rprx-vision,show=protocol:vless"`
	Method      string              `json:"method,omitempty" ui:"label=Cipher,options=2022-blake3-aes-128-gcm|2022-blake3-aes-256-gcm|2022-blake3-chacha20-poly1305|chacha20-ietf-poly1305|aes-128-gcm|aes-256-gcm,show=protocol:shadowsocks"`
	ServerKey   string              `json:"server_key,omitempty" ui:"label=Server key,show=protocol:shadowsocks"`
	UpMbps      int                 `json:"up_mbps,omitempty" ui:"label=Server upload (Mbps),hint=How fast the server sends at most. Clients get it as their download speed. Empty leaves it to the client.,show=protocol:hysteria2,advanced"`
	DownMbps    int                 `json:"down_mbps,omitempty" ui:"label=Server download (Mbps),hint=How fast the server receives at most. Clients get it as their upload speed.,show=protocol:hysteria2,advanced"`
	Obfs        string              `json:"obfs,omitempty" ui:"label=Obfuscation,options=|salamander,show=protocol:hysteria2,advanced"`
	ObfsPass    string              `json:"obfs_pass,omitempty" ui:"label=Obfuscation password,show=protocol:hysteria2,advanced"`
	Masquerade  string              `json:"masquerade,omitempty" ui:"label=Masquerade URL,show=protocol:hysteria2,advanced"`
	Ports       string              `json:"ports,omitempty" ui:"label=Port hopping range,hint=Clients hop between ports in this range like 20000-30000. Forward the range to the inbound port on the node yourself. The panel does not.,show=protocol:hysteria2,advanced"`
	CongestCtl  string              `json:"congestion,omitempty" ui:"label=Congestion control,options=bbr|cubic|new_reno,show=protocol:tuic,advanced"`
	ZeroRTT     bool                `json:"zero_rtt,omitempty" ui:"label=0-RTT,show=protocol:tuic,advanced"`
	Heartbeat   string              `json:"heartbeat,omitempty" ui:"label=Heartbeat,show=protocol:tuic,advanced"`
	Handshake   string              `json:"handshake,omitempty" ui:"label=Handshake server,hint=host:port,show=protocol:shadowtls"`
	STLSDetour  string              `json:"detour,omitempty" ui:"label=Detour inbound tag,show=protocol:shadowtls,advanced"`
	PaddingSch  string              `json:"padding,omitempty" ui:"label=Padding scheme,show=protocol:anytls,advanced"`
	WGSubnet    string              `json:"wg_subnet,omitempty" ui:"label=Tunnel subnet,hint=Each user gets one address from it. Example 10.8.0.0/16,show=protocol:wireguard"`
	WGPrivate   string              `json:"wg_private,omitempty" ui:"label=Server private key,show=protocol:wireguard,advanced"`
	WGPublic    string              `json:"wg_public,omitempty" ui:"label=Server public key,show=protocol:wireguard,advanced"`
	WGMTU       int                 `json:"wg_mtu,omitempty" ui:"label=MTU,show=protocol:wireguard,advanced"`
	WGDNS       string              `json:"wg_dns,omitempty" ui:"label=DNS for clients,show=protocol:wireguard,advanced"`
	MTMode      string              `json:"mt_mode,omitempty" ui:"label=Disguise,options=faketls|padded,show=protocol:mtproto"`
	MTDomain    string              `json:"mt_domain,omitempty" ui:"label=Cover site,hint=A real site Telegram traffic pretends to be. Unrecognised visitors are sent there.,show=protocol:mtproto"`
	TPlatform   string              `json:"t_platform,omitempty" ui:"label=Platform,options=vk.com,show=protocol:turnable"`
	TCallID     string              `json:"t_call_id,omitempty" ui:"label=Call ID,hint=The code at the end of a vk.com/call/join/ link,show=protocol:turnable"`
	TProto      string              `json:"t_proto,omitempty" ui:"label=Tunnel protocol,options=dtls|srtp|none,show=protocol:turnable,advanced"`
	TRoutes     []TurnableRouteSpec `json:"t_routes,omitempty"` // where the tunnel leads, one entry per destination
	TTarget     string              `json:"t_target,omitempty"` // older single destination, read as the route "main"
	TSocket     string              `json:"t_socket,omitempty"`
	TTransport  string              `json:"t_transport,omitempty"`
	TEncryption string              `json:"t_encryption,omitempty"`
	TPeers      int                 `json:"t_peers,omitempty" ui:"label=Peer connections per session,hint=How many TURN connections a client opens at once. One session carries every destination. 5 when empty.,show=protocol:turnable,advanced"`
	TPrivate    string              `json:"t_private,omitempty" ui:"label=Server private key,show=protocol:turnable,advanced"`
	TPublic     string              `json:"t_public,omitempty" ui:"label=Server public key,show=protocol:turnable,advanced"`
	NaiveDest   string              `json:"naive_dest,omitempty" ui:"label=Site address,hint=Where visitors and failed logins are sent, as host:port. Usually your web server.,show=core:naive"`
	NaiveTLS    bool                `json:"naive_dest_tls,omitempty" ui:"label=Site uses HTTPS,show=core:naive"`
	NaiveSNI    string              `json:"naive_dest_sni,omitempty" ui:"label=Site server name,hint=Sent to the site over HTTPS. Empty uses the name the visitor asked for.,show=core:naive,advanced"`
	NaiveSkip   bool                `json:"naive_dest_insecure,omitempty" ui:"label=Skip site certificate check,show=core:naive,advanced"`
	NaiveProxy  string              `json:"naive_dest_proxy,omitempty" ui:"label=PROXY protocol to the site,hint=Tells the site the visitor's real address,options=|v1|v2,show=core:naive"`
	NaiveHeader string              `json:"naive_ip_header,omitempty" ui:"label=Client IP header,hint=Header that carries the visitor's address to the site. Empty means X-Forwarded-For and none means no header.,show=core:naive"`
	TJDest      string              `json:"trojan_dest,omitempty" ui:"label=Site address,hint=Where visitors and failed logins are sent once TLS is off, as host:port. Usually your web server.,show=core:trojan"`
	TJTLS       bool                `json:"trojan_dest_tls,omitempty" ui:"label=Site uses HTTPS,show=core:trojan"`
	TJSNI       string              `json:"trojan_dest_sni,omitempty" ui:"label=Site server name,hint=Sent to the site over HTTPS. Empty uses the name the visitor asked for.,show=core:trojan,advanced"`
	TJSkip      bool                `json:"trojan_dest_insecure,omitempty" ui:"label=Skip site certificate check,show=core:trojan,advanced"`
	TJProxy     string              `json:"trojan_dest_proxy,omitempty" ui:"label=PROXY protocol to the site,hint=Tells the site the visitor's real address,options=|v1|v2,show=core:trojan"`
	TJIPHeader  string              `json:"trojan_ip_header,omitempty" ui:"label=Client IP header,hint=Reads visitors' HTTP requests and puts their address in this header, such as X-Forwarded-For. Empty passes the stream on untouched.,show=core:trojan"`
	TJHeaders   map[string]string   `json:"trojan_dest_headers,omitempty" ui:"label=Extra site headers,hint=Set on every request to the site. Like the client IP header this makes the daemon read HTTP.,show=core:trojan,advanced"`
	TJBySNI     map[string]string   `json:"trojan_sni_dest,omitempty" ui:"label=Site by server name,hint=A server name or *.example.com to host:port. Checked before ALPN and path.,show=core:trojan,advanced"`
	TJByALPN    map[string]string   `json:"trojan_alpn_dest,omitempty" ui:"label=Site by ALPN,hint=An ALPN such as h2 to host:port.,show=core:trojan,advanced"`
	TJByPath    map[string]string   `json:"trojan_path_dest,omitempty" ui:"label=Site by path,hint=A path prefix such as /blog to host:port. HTTP/1 only.,show=core:trojan,advanced"`
	TJPlain     string              `json:"trojan_plain,omitempty" ui:"label=Plain HTTP visitors,hint=What someone speaking plain HTTP to this port gets. Empty closes the connection.,options=|site|redirect|nginx,show=core:trojan,advanced"`
	TJMinTLS    string              `json:"trojan_tls_min,omitempty" ui:"label=Lowest TLS version,options=|1.2|1.3,show=core:trojan,advanced"`
	TJCiphers   []string            `json:"trojan_ciphers,omitempty" ui:"label=TLS 1.2 cipher suites,hint=Go names such as TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256. TLS 1.3 suites are fixed.,show=core:trojan,advanced"`
	TJCurves    []string            `json:"trojan_curves,omitempty" ui:"label=Key exchange groups,hint=X25519MLKEM768 X25519 P-256 P-384 or P-521 in order of preference,show=core:trojan,advanced"`
	TJNoTicket  bool                `json:"trojan_no_tickets,omitempty" ui:"label=Turn off session tickets,show=core:trojan,advanced"`
	TJUDPIdle   int                 `json:"trojan_udp_timeout,omitempty" ui:"label=UDP idle timeout (s),hint=60 when empty,show=core:trojan,advanced"`
	TJFastOpen  bool                `json:"trojan_fast_open,omitempty" ui:"label=TCP Fast Open,show=core:trojan,advanced"`
	TJReuse     bool                `json:"trojan_reuse_port,omitempty" ui:"label=Reuse port,show=core:trojan,advanced"`
	TJNagle     bool                `json:"trojan_nagle,omitempty" ui:"label=Keep Nagle's algorithm,show=core:trojan,advanced"`
	TJNoAlive   bool                `json:"trojan_no_keepalive,omitempty" ui:"label=Turn off TCP keep-alive,show=core:trojan,advanced"`
	WGAddress   string              `json:"wg_address,omitempty"` // a user's own tunnel address, filled in for client profiles
	Auth        bool                `json:"auth,omitempty" ui:"label=Require auth,show=protocol:socks|http|mixed"`
	UDP         bool                `json:"udp,omitempty"` // unused, socks inbounds always carry UDP
	Mux         *Mux                `json:"mux,omitempty"`
	Fragment    *Frag               `json:"fragment,omitempty"`
	AcceptProxy bool                `json:"accept_proxy,omitempty"` // expect a PROXY protocol header, set when an edge sits in front
	Guard       *Guard              `json:"guard,omitempty"`
}

// Guard defaults.
const (
	GuardInterval = 30
	GuardTimeout  = 5
	GuardFailures = 3
	GuardGiveUp   = 3
)

// Guard watches an inbound that cloaks as a real site. While the core is down the daemon serves the port itself and
// passes every connection to the site, and a core that stops answering is restarted.
type Guard struct {
	Enabled  bool   `json:"enabled"`
	Target   string `json:"target,omitempty"`   // host:port of the real site, taken from the inbound when empty
	SNI      string `json:"sni,omitempty"`      // server name the probes send, taken from the inbound when empty
	XVer     *int   `json:"xver,omitempty"`     // PROXY header version sent to the target, taken from the inbound when nil
	Interval int    `json:"interval,omitempty"` // seconds between probes
	Timeout  int    `json:"timeout,omitempty"`  // seconds one probe may take
	Failures int    `json:"failures,omitempty"` // failed probes in a row before the core is restarted
	Takeover *bool  `json:"takeover,omitempty"` // serve the port while the core is down, on when nil
	Restart  *bool  `json:"restart,omitempty"`  // restart a core that stops answering, on when nil
	GiveUp   int    `json:"give_up,omitempty"`  // failed recoveries in a row before the core is stopped and the site served directly
}

// Mux is client side multiplexing, advertised to clients through subscriptions.
type Mux struct {
	Enabled     bool   `json:"enabled" ui:"label=Multiplex"`
	Protocol    string `json:"protocol,omitempty" ui:"label=Mux protocol,options=h2mux|smux|yamux,advanced"`
	Concurrency int    `json:"concurrency,omitempty" ui:"label=Concurrency,advanced"`
	Padding     bool   `json:"padding,omitempty" ui:"label=Padding,advanced"`
}

// Frag is client side TLS fragmentation, advertised to clients through subscriptions.
type Frag struct {
	Enabled  bool   `json:"enabled" ui:"label=Fragment TLS hello"`
	Packets  string `json:"packets,omitempty" ui:"label=Packets,advanced"`
	Length   string `json:"length,omitempty" ui:"label=Length,advanced"`
	Interval string `json:"interval,omitempty" ui:"label=Interval (ms),advanced"`
}

// Outbound kinds.
const (
	OutDirect = "direct"
	OutBlock  = "block"
	OutProxy  = "proxy"
	OutWarp   = "warp"
)

// Outbound is where traffic leaves the daemon.
type Outbound struct {
	Tag       string    `json:"tag"`
	Kind      string    `json:"kind"`
	Upstream  *Upstream `json:"upstream,omitempty"`
	Interface string    `json:"interface,omitempty"` // bind to a network interface
	Strategy  string    `json:"strategy,omitempty"`  // domain strategy for direct
	Warp      *Warp     `json:"warp,omitempty"`      // a WireGuard exit, used by the warp kind
}

// Warp is a WireGuard identity a core dials out with.
type Warp struct {
	PrivateKey string   `json:"private_key"`
	PeerKey    string   `json:"peer_key"`
	Addresses  []string `json:"addresses"` // with prefix lengths
	Endpoint   string   `json:"endpoint"`  // host:port
	Reserved   [3]int   `json:"reserved"`
	MTU        int      `json:"mtu,omitempty"`
}

// Upstream is a remote proxy server, used for chained outbounds and for client profiles.
type Upstream struct {
	Name      string    `json:"name"`
	Protocol  string    `json:"protocol"`
	Address   string    `json:"address"`
	Port      int       `json:"port"`
	UUID      string    `json:"uuid,omitempty"`
	Password  string    `json:"password,omitempty"`
	Username  string    `json:"username,omitempty"`
	Transport Transport `json:"transport"`
	Security  Security  `json:"security"`
	Options   Options   `json:"options"`
	Inner     *Upstream `json:"inner,omitempty"`    // what runs inside this one, e.g. shadowsocks under shadowtls
	RawLink   string    `json:"raw_link,omitempty"` // a link written by hand, served exactly as it is
}

// Rule routes matching traffic to an outbound.
type Rule struct {
	Name         string   `json:"name,omitempty"`
	InboundTags  []string `json:"inbound_tags,omitempty"`
	Users        []string `json:"users,omitempty"`
	Domain       []string `json:"domain,omitempty"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	DomainKw     []string `json:"domain_keyword,omitempty"`
	GeoSite      []string `json:"geosite,omitempty"`
	GeoIP        []string `json:"geoip,omitempty"`
	IPCIDR       []string `json:"ip_cidr,omitempty"`
	Port         []string `json:"port,omitempty"`
	Network      string   `json:"network,omitempty"`
	Protocol     []string `json:"protocol,omitempty"` // sniffed protocol such as bittorrent or quic
	Outbound     string   `json:"outbound"`
}
