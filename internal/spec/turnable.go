package spec

import (
	"crypto/mlkem"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// TurnableRoute is the id the single route of an older, flat inbound gets.
const TurnableRoute = "main"

// Turnable defaults, used when an option is left empty.
const (
	TurnablePlatform   = "vk.com"
	TurnableProto      = "dtls"
	TurnableTransport  = "mpath"
	TurnableEncryption = "handshake"
	TurnablePeers      = 5
)

// TurnableRouteSpec is one destination a Turnable tunnel can lead to. A server offers several and every
// user may use all of them, the client picks one by its id.
type TurnableRouteSpec struct {
	ID         string `json:"id"`
	Name       string `json:"name,omitempty"` // a template, see RouteNamePlaceholders; empty means {remark}
	Target     string `json:"target"`         // ip:port, filled in from the inbound for the "inbound" kind
	Socket     string `json:"socket"`         // tcp or udp
	Transport  string `json:"transport,omitempty"`
	Encryption string `json:"encryption,omitempty"`

	// What apps other than Turnable itself are given for this destination. Turnable apps always get all of them.
	Kind      string `json:"kind,omitempty"`       // external (the default), inbound or custom
	InboundID int64  `json:"inbound_id,omitempty"` // inbound kind: the inbound the tunnel leads to
	URL       string `json:"url,omitempty"`        // custom kind: a link template, see RouteURLVars
	LocalPort int    `json:"local_port,omitempty"` // where the Turnable app listens on the device, which the link then points at
}

// Kinds of route, by what other apps get.
const (
	RouteExternal = "external" // nothing, only Turnable apps see it
	RouteInbound  = "inbound"  // the link of one of the panel's own inbounds
	RouteCustom   = "custom"   // a link written by hand
)

// IsLocal reports whether apps other than Turnable are given a link for the route.
func (r TurnableRouteSpec) IsLocal() bool { return r.Kind == RouteInbound || r.Kind == RouteCustom }

var routeID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// Split breaks the destination into an address and a port.
func (r TurnableRouteSpec) Split() (string, int, error) {
	host, port, err := net.SplitHostPort(r.Target)
	if err != nil {
		return "", 0, fmt.Errorf("the destination must look like 10.0.0.1:443")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, fmt.Errorf("the destination port %q is not valid", port)
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return "", 0, fmt.Errorf("the destination host must be an IP address")
	}
	return host, n, nil
}

// withDefaults fills what a route leaves empty.
func (r TurnableRouteSpec) withDefaults() TurnableRouteSpec {
	if r.Transport == "" {
		r.Transport = TurnableTransport
	}
	if r.Encryption == "" {
		r.Encryption = TurnableEncryption
	}
	return r
}

// TurnableRoutes lists the destinations of an inbound, with defaults applied. Inbounds saved before routes
// existed carry a single flat destination, which comes out as the route "main".
func (o Options) TurnableRoutes() []TurnableRouteSpec {
	if len(o.TRoutes) == 0 {
		if o.TTarget == "" && o.TSocket == "" {
			return nil
		}
		legacy := TurnableRouteSpec{ID: TurnableRoute, Target: o.TTarget, Socket: o.TSocket, Transport: o.TTransport, Encryption: o.TEncryption}
		return []TurnableRouteSpec{legacy.withDefaults()}
	}
	out := make([]TurnableRouteSpec, len(o.TRoutes))
	for i, r := range o.TRoutes {
		out[i] = r.withDefaults()
	}
	return out
}

// MigrateTurnable moves an older flat destination into the route list, so what gets stored has one shape.
func (o Options) MigrateTurnable() Options {
	if len(o.TRoutes) == 0 && (o.TTarget != "" || o.TSocket != "") {
		o.TRoutes = []TurnableRouteSpec{{ID: TurnableRoute, Target: o.TTarget, Socket: o.TSocket, Transport: o.TTransport, Encryption: o.TEncryption}}
	}
	o.TTarget, o.TSocket, o.TTransport, o.TEncryption = "", "", "", ""
	return o
}

// validateTurnable checks the Turnable fields of an inbound.
func (o Options) validateTurnable() error {
	if p := o.TPlatform; p != "" && p != TurnablePlatform {
		return Invalid("options.t_platform", "unknown platform %q", p)
	}
	if o.TCallID == "" {
		return Invalid("options.t_call_id", "a call id is required")
	}
	switch o.TProto {
	case "", "dtls", "srtp", "none":
	default:
		return Invalid("options.t_proto", "unknown wrapper %q", o.TProto)
	}
	if o.TPeers < 0 {
		return Invalid("options.t_peers", "peer connections cannot be negative")
	}
	if err := o.validateTurnableRoutes(); err != nil {
		return err
	}
	pub, err := base64.StdEncoding.DecodeString(o.TPublic)
	if err != nil {
		return Invalid("options.t_public", "the public key is not base64")
	}
	if _, err := mlkem.NewEncapsulationKey768(pub); err != nil {
		return Invalid("options.t_public", "the public key is not an ML-KEM-768 key")
	}
	priv, err := base64.StdEncoding.DecodeString(o.TPrivate)
	if err != nil {
		return Invalid("options.t_private", "the private key is not base64")
	}
	if _, err := mlkem.NewDecapsulationKey768(priv); err != nil {
		return Invalid("options.t_private", "the private key is not an ML-KEM-768 key")
	}
	return nil
}

// validateTurnableRoutes checks every destination, naming the field of the first one that is wrong.
func (o Options) validateTurnableRoutes() error {
	routes := o.TurnableRoutes()
	if len(routes) == 0 {
		return Invalid("options.t_routes", "add at least one destination")
	}
	seen := map[string]bool{}
	ports := map[int]bool{}
	for i, r := range routes {
		at := func(f string) string { return "options.t_routes." + strconv.Itoa(i) + "." + f }
		if !routeID.MatchString(r.ID) {
			return Invalid(at("id"), "use lowercase letters, digits, - and _ for the id, up to 32 characters")
		}
		if seen[r.ID] {
			return Invalid(at("id"), "another destination already uses the id %q", r.ID)
		}
		seen[r.ID] = true
		if err := CheckPlaceholders(r.Name, RouteNamePlaceholders); err != nil {
			return Invalid(at("name"), "%s", err)
		}
		if _, _, err := r.Split(); err != nil {
			return Invalid(at("target"), "%s", err)
		}
		switch r.Socket {
		case "tcp", "udp":
		default:
			return Invalid(at("socket"), "pick tcp or udp for the destination socket")
		}
		switch r.Transport {
		case "mpath", "kcp", "sctp", "none":
		default:
			return Invalid(at("transport"), "unknown route transport %q", r.Transport)
		}
		if r.Socket == "tcp" && r.Transport == "none" {
			return Invalid(at("transport"), "tcp needs a route transport other than none")
		}
		if err := r.validateKind(at); err != nil {
			return err
		}
		if r.IsLocal() {
			if ports[r.LocalPort] {
				return Invalid(at("local_port"), "another destination already uses the port %d", r.LocalPort)
			}
			ports[r.LocalPort] = true
		}
		switch r.Encryption {
		case "handshake", "full":
		default:
			return Invalid(at("encryption"), "unknown encryption mode %q", r.Encryption)
		}
	}
	return nil
}

// TurnableDefaults fills the options that have a default.
func (o Options) TurnableDefaults() Options {
	if o.TPlatform == "" {
		o.TPlatform = TurnablePlatform
	}
	if o.TProto == "" {
		o.TProto = TurnableProto
	}
	if o.TPeers == 0 {
		o.TPeers = TurnablePeers
	}
	o.TRoutes = o.TurnableRoutes()
	o.TTarget, o.TSocket, o.TTransport, o.TEncryption = "", "", "", ""
	return o
}

// validateKind checks what a route offers to apps other than Turnable.
func (r TurnableRouteSpec) validateKind(at func(string) string) error {
	switch r.Kind {
	case "", RouteExternal:
		return nil
	case RouteInbound:
		if r.InboundID <= 0 {
			return Invalid(at("inbound_id"), "pick the inbound this destination leads to")
		}
	case RouteCustom:
		if strings.TrimSpace(r.URL) == "" {
			return Invalid(at("url"), "write the link other apps should get")
		}
		if !strings.Contains(r.URL, "://") {
			return Invalid(at("url"), "a link starts with a scheme, like vless://")
		}
		if err := CheckPlaceholders(r.URL, RouteURLVars); err != nil {
			return Invalid(at("url"), "%s", err)
		}
	default:
		return Invalid(at("kind"), "unknown kind %q", r.Kind)
	}
	if r.LocalPort < 1 || r.LocalPort > 65535 {
		return Invalid(at("local_port"), "pick the port the Turnable app listens on, from 1 to 65535")
	}
	return nil
}
