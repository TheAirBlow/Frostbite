// Package spec is the core-agnostic description of what a daemon should run.
package spec

import "encoding/json"

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
	RouteOnly    bool `json:"route_only" ui:"label=Route only,advanced"`
	DestOverride bool `json:"dest_override" ui:"label=Override destination,advanced"`
}

// Transport describes the stream layer under the proxy protocol.
type Transport struct {
	Type        string            `json:"type" ui:"label=Transport,options=tcp|ws|grpc|httpupgrade|xhttp|kcp"`
	Path        string            `json:"path,omitempty" ui:"label=Path,show=type:ws|httpupgrade|xhttp"`
	Host        string            `json:"host,omitempty" ui:"label=Host header,show=type:ws|httpupgrade|xhttp,advanced"`
	ServiceName string            `json:"service_name,omitempty" ui:"label=gRPC service name,show=type:grpc"`
	Mode        string            `json:"mode,omitempty" ui:"label=XHTTP mode,options=auto|packet-up|stream-up|stream-one,show=type:xhttp,advanced"`
	Headers     map[string]string `json:"headers,omitempty" ui:"label=Extra headers,advanced"`
	EarlyData   int               `json:"early_data,omitempty" ui:"label=Max early data,show=type:ws,advanced"`
	KCPSeed     string            `json:"kcp_seed,omitempty" ui:"label=mKCP seed,show=type:kcp,advanced"`
}

// Security describes the TLS layer. Server-only fields never leave the panel in client output.
type Security struct {
	Type        string   `json:"type" ui:"label=Security,options=none|tls|reality"`
	SNI         string   `json:"sni,omitempty" ui:"label=SNI,show=type:tls"`
	ALPN        []string `json:"alpn,omitempty" ui:"label=ALPN,advanced"`
	Fingerprint string   `json:"fingerprint,omitempty" ui:"label=uTLS fingerprint,options=|chrome|firefox|safari|ios|android|edge|random,advanced"`
	Insecure    bool     `json:"insecure,omitempty" ui:"label=Allow insecure,advanced"`
	CertPath    string   `json:"cert_path,omitempty" ui:"label=Certificate path,show=type:tls"`
	KeyPath     string   `json:"key_path,omitempty" ui:"label=Key path,show=type:tls"`
	ECHKey      string   `json:"ech_key,omitempty" ui:"label=ECH key,show=type:tls,advanced"`
	ECHConfig   string   `json:"ech_config,omitempty" ui:"label=ECH config,show=type:tls,advanced"`
	Reality     *Reality `json:"reality,omitempty"`
	ACME        *ACME    `json:"acme,omitempty"`
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
	Flow        string `json:"flow,omitempty" ui:"label=Flow,options=|xtls-rprx-vision,show=protocol:vless"`
	Method      string `json:"method,omitempty" ui:"label=Cipher,options=2022-blake3-aes-128-gcm|2022-blake3-aes-256-gcm|2022-blake3-chacha20-poly1305|chacha20-ietf-poly1305|aes-128-gcm|aes-256-gcm,show=protocol:shadowsocks"`
	ServerKey   string `json:"server_key,omitempty" ui:"label=Server key,show=protocol:shadowsocks"`
	UpMbps      int    `json:"up_mbps,omitempty" ui:"label=Upload limit (Mbps),show=protocol:hysteria2,advanced"`
	DownMbps    int    `json:"down_mbps,omitempty" ui:"label=Download limit (Mbps),show=protocol:hysteria2,advanced"`
	Obfs        string `json:"obfs,omitempty" ui:"label=Obfuscation,options=|salamander,show=protocol:hysteria2,advanced"`
	ObfsPass    string `json:"obfs_pass,omitempty" ui:"label=Obfuscation password,show=protocol:hysteria2,advanced"`
	Masquerade  string `json:"masquerade,omitempty" ui:"label=Masquerade URL,show=protocol:hysteria2,advanced"`
	Ports       string `json:"ports,omitempty" ui:"label=Port hopping range,hint=e.g. 20000-30000,show=protocol:hysteria2|tuic,advanced"`
	CongestCtl  string `json:"congestion,omitempty" ui:"label=Congestion control,options=bbr|cubic|new_reno,show=protocol:tuic|hysteria2,advanced"`
	ZeroRTT     bool   `json:"zero_rtt,omitempty" ui:"label=0-RTT,show=protocol:tuic,advanced"`
	Heartbeat   string `json:"heartbeat,omitempty" ui:"label=Heartbeat,show=protocol:tuic,advanced"`
	Handshake   string `json:"handshake,omitempty" ui:"label=Handshake server,hint=host:port,show=protocol:shadowtls"`
	STLSDetour  string `json:"detour,omitempty" ui:"label=Detour inbound tag,show=protocol:shadowtls,advanced"`
	PaddingSch  string `json:"padding,omitempty" ui:"label=Padding scheme,show=protocol:anytls,advanced"`
	WGSubnet    string `json:"wg_subnet,omitempty" ui:"label=Tunnel subnet,hint=Each user gets one address from it. Example 10.8.0.0/16,show=protocol:wireguard"`
	WGPrivate   string `json:"wg_private,omitempty" ui:"label=Server private key,show=protocol:wireguard,advanced"`
	WGPublic    string `json:"wg_public,omitempty" ui:"label=Server public key,show=protocol:wireguard,advanced"`
	WGMTU       int    `json:"wg_mtu,omitempty" ui:"label=MTU,show=protocol:wireguard,advanced"`
	WGDNS       string `json:"wg_dns,omitempty" ui:"label=DNS for clients,show=protocol:wireguard,advanced"`
	MTMode      string `json:"mt_mode,omitempty" ui:"label=Disguise,options=faketls|padded,show=protocol:mtproto"`
	MTDomain    string `json:"mt_domain,omitempty" ui:"label=Cover site,hint=A real site Telegram traffic pretends to be. Unrecognised visitors are sent there.,show=protocol:mtproto"`
	TPlatform   string `json:"t_platform,omitempty" ui:"label=Platform,options=vk.com,show=protocol:turnable"`
	TCallID     string `json:"t_call_id,omitempty" ui:"label=Call ID,hint=The code at the end of a vk.com/call/join/ link,show=protocol:turnable"`
	TProto      string `json:"t_proto,omitempty" ui:"label=Tunnel protocol,options=dtls|srtp|none,show=protocol:turnable,advanced"`
	TTarget     string `json:"t_target,omitempty" ui:"label=Destination,hint=Where the tunnel leads, as ip:port. Usually an inbound on this node.,show=protocol:turnable"`
	TSocket     string `json:"t_socket,omitempty" ui:"label=Network,options=tcp|udp,show=protocol:turnable"`
	TTransport  string `json:"t_transport,omitempty" ui:"label=Transport,options=mpath|kcp|sctp|none,show=protocol:turnable,advanced"`
	TEncryption string `json:"t_encryption,omitempty" ui:"label=Encryption,options=handshake|full,show=protocol:turnable,advanced"`
	TPeers      int    `json:"t_peers,omitempty" ui:"label=Connections per user,show=protocol:turnable,advanced"`
	TPrivate    string `json:"t_private,omitempty" ui:"label=Server private key,show=protocol:turnable,advanced"`
	TPublic     string `json:"t_public,omitempty" ui:"label=Server public key,show=protocol:turnable,advanced"`
	WGAddress   string `json:"wg_address,omitempty"` // a user's own tunnel address, filled in for client profiles
	Auth        bool   `json:"auth,omitempty" ui:"label=Require auth,show=protocol:socks|http|mixed"`
	UDP         bool   `json:"udp,omitempty" ui:"label=Allow UDP,show=protocol:socks|mixed,advanced"`
	Mux         *Mux   `json:"mux,omitempty"`
	Fragment    *Frag  `json:"fragment,omitempty"`
	AcceptProxy bool   `json:"accept_proxy,omitempty"` // expect a PROXY protocol header, set when an edge sits in front
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
	Inner     *Upstream `json:"inner,omitempty"` // what runs inside this one, e.g. shadowsocks under shadowtls
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
