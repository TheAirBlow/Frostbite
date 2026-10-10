package spec

import (
	"fmt"
	"net"
	"reflect"
	"strings"
)

// Validate makes sure a daemon spec is coherent before it is sent anywhere.
func (d *Daemon) Validate() error {
	if d.Edge != nil {
		return d.Edge.validate()
	}
	tags := map[string]bool{}
	ports := map[string]string{}
	for _, in := range d.Inbounds {
		if in.Tag == "" {
			return Invalid("tag", "inbound without a tag")
		}
		if tags[in.Tag] {
			return Invalid("tag", "another inbound on this daemon already uses the tag %q", in.Tag)
		}
		tags[in.Tag] = true
		if in.Port < 1 || in.Port > 65535 {
			return Invalid("port", "port %d is out of range, use 1 to 65535", in.Port)
		}
		key := fmt.Sprintf("%s/%d", udpOrTCP(in), in.Port)
		if other, ok := ports[key]; ok && in.Listen == "" {
			return Invalid("port", "port %d is already used by %s", in.Port, other)
		}
		ports[key] = in.Tag
		if err := in.validateSecurity(); err != nil {
			return err
		}
		if in.Protocol == ProtoForward && (in.Forward == nil || in.Forward.Address == "" || in.Forward.Port == 0) {
			return Invalid("forward.address", "the relay needs a target address and port")
		}
	}

	outs := map[string]bool{}
	for _, o := range d.Outbounds {
		if o.Tag == "" {
			return fmt.Errorf("outbound without a tag")
		}
		if outs[o.Tag] {
			return fmt.Errorf("duplicate outbound tag %q", o.Tag)
		}
		outs[o.Tag] = true
		if o.Kind == OutProxy && (o.Upstream == nil || o.Upstream.Address == "") {
			return fmt.Errorf("outbound %s: upstream is missing", o.Tag)
		}
	}
	for i, r := range d.Rules {
		if !outs[r.Outbound] {
			return fmt.Errorf("rule %d: unknown outbound %q", i+1, r.Outbound)
		}
	}
	if d.Final != "" && !outs[d.Final] {
		return fmt.Errorf("final outbound %q does not exist", d.Final)
	}
	return nil
}

// validateSecurity checks the TLS side of one inbound.
func (in Inbound) validateSecurity() error {
	switch in.Security.Type {
	case SecurityReality:
		r := in.Security.Reality
		if r == nil || r.Dest == "" || r.PrivateKey == "" || len(r.ServerNames) == 0 {
			return reality(r)
		}
		if _, _, err := net.SplitHostPort(r.Dest); err != nil {
			return Invalid("security.reality.dest", "the handshake target must look like host:port")
		}
		if r.XVer < 0 || r.XVer > 2 {
			return Invalid("security.reality.xver", "the PROXY header version must be 0, 1 or 2")
		}
	case SecurityTLS:
		if a := in.Security.ACME; a != nil {
			if a.Domain == "" || net.ParseIP(a.Domain) != nil {
				return Invalid("security.acme.domain", "automatic certificates need a domain name, not an address")
			}
		} else if in.Security.CertPath == "" || in.Security.KeyPath == "" {
			if in.Security.CertPath == "" {
				return Invalid("security.cert_path", "tls needs a certificate")
			}
			return Invalid("security.key_path", "tls needs a key")
		}
	}
	switch in.Protocol {
	case ProtoHysteria2, ProtoTUIC, ProtoAnyTLS, ProtoNaive:
		if in.Security.Type != SecurityTLS {
			return Invalid("security.type", "%s requires tls", in.Protocol)
		}
	case ProtoMTProto:
		if in.Security.Type != "" && in.Security.Type != SecurityNone {
			return Invalid("security.type", "mtproto brings its own disguise, leave security off")
		}
		switch in.Options.MTMode {
		case "padded":
		case "faketls", "":
			if in.Options.MTDomain == "" {
				return Invalid("options.mt_domain", "mtproto needs a cover site for the faketls disguise")
			}
		default:
			return Invalid("options.mt_mode", "unknown mtproto disguise %q", in.Options.MTMode)
		}
	case ProtoTurnable:
		if in.Security.Type != "" && in.Security.Type != SecurityNone {
			return Invalid("security.type", "turnable brings its own encryption, leave security off")
		}
		if err := in.Options.validateTurnable(); err != nil {
			return err
		}
	case ProtoWireGuard:
		if in.Options.WGPrivate == "" {
			return Invalid("options.wg_private", "wireguard needs a server key")
		}
		if _, err := WGServerAddress(in.Options.WGSubnet); err != nil {
			return Invalid("options.wg_subnet", "%s", err)
		}
	}
	return nil
}

// udpOrTCP says which socket family an inbound binds, so the same port can be shared across both.
func udpOrTCP(in Inbound) string {
	switch in.Protocol {
	case ProtoHysteria2, ProtoTUIC, ProtoWireGuard, ProtoTurnable:
		return "udp"
	}
	if in.Transport.Type == TransportKCP {
		return "udp"
	}
	return "tcp"
}

// Network reports whether the inbound listens on udp or tcp.
func (in Inbound) Network() string { return udpOrTCP(in) }

// IsLoopback reports whether the listen address is only reachable locally.
func (in Inbound) IsLoopback() bool {
	return strings.HasPrefix(in.Listen, "127.") || in.Listen == "::1" || in.Listen == "localhost"
}

// validate checks an edge description.
func (e *Edge) validate() error {
	if len(e.Listen) == 0 {
		return fmt.Errorf("the edge needs at least one address to listen on")
	}
	for _, l := range e.Listen {
		if _, _, err := net.SplitHostPort(l); err != nil {
			return fmt.Errorf("listen address %q must look like :443 or 0.0.0.0:443", l)
		}
	}
	for i, r := range e.Routes {
		if len(r.SNI) == 0 {
			return fmt.Errorf("route %d (%s) matches no server name", i+1, r.Name)
		}
		if _, _, err := net.SplitHostPort(r.Target); err != nil {
			return fmt.Errorf("route %d (%s): target %q must look like host:port", i+1, r.Name, r.Target)
		}
	}
	if e.Default != "" {
		if _, _, err := net.SplitHostPort(e.Default); err != nil {
			return fmt.Errorf("default target %q must look like host:port", e.Default)
		}
	}
	return nil
}

// SameShape reports whether two specs differ in nothing but their users, which cores may be able to apply without a restart.
func SameShape(a, b Daemon) bool {
	strip := func(d Daemon) Daemon {
		d.Revision = 0
		ins := make([]Inbound, len(d.Inbounds))
		copy(ins, d.Inbounds)
		for i := range ins {
			ins[i].Users = nil
		}
		d.Inbounds = ins
		return d
	}
	return reflect.DeepEqual(strip(a), strip(b))
}

// reality names the first thing a REALITY setup is missing.
func reality(r *Reality) error {
	switch {
	case r == nil || r.Dest == "":
		return Invalid("security.reality.dest", "reality needs a handshake target")
	case len(r.ServerNames) == 0:
		return Invalid("security.reality.server_names", "reality needs at least one server name")
	default:
		return Invalid("security.reality.private_key", "reality needs a private key")
	}
}
