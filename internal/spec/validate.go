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
			return fmt.Errorf("inbound without a tag")
		}
		if tags[in.Tag] {
			return fmt.Errorf("duplicate inbound tag %q", in.Tag)
		}
		tags[in.Tag] = true
		if in.Port < 1 || in.Port > 65535 {
			return fmt.Errorf("inbound %s: port %d is out of range", in.Tag, in.Port)
		}
		key := fmt.Sprintf("%s/%d", udpOrTCP(in), in.Port)
		if other, ok := ports[key]; ok && in.Listen == "" {
			return fmt.Errorf("inbound %s: port %d is already used by %s", in.Tag, in.Port, other)
		}
		ports[key] = in.Tag
		if err := in.validateSecurity(); err != nil {
			return fmt.Errorf("inbound %s: %w", in.Tag, err)
		}
		if in.Protocol == ProtoForward && (in.Forward == nil || in.Forward.Address == "" || in.Forward.Port == 0) {
			return fmt.Errorf("inbound %s: forward target is missing", in.Tag)
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
			return fmt.Errorf("reality needs a target, server names and a private key")
		}
		if _, _, err := net.SplitHostPort(r.Dest); err != nil {
			return fmt.Errorf("reality target must look like host:port")
		}
	case SecurityTLS:
		if a := in.Security.ACME; a != nil {
			if a.Domain == "" || net.ParseIP(a.Domain) != nil {
				return fmt.Errorf("automatic certificates need a domain name, not an address")
			}
		} else if in.Security.CertPath == "" || in.Security.KeyPath == "" {
			return fmt.Errorf("tls needs a certificate and a key")
		}
	}
	switch in.Protocol {
	case ProtoHysteria2, ProtoTUIC, ProtoAnyTLS, ProtoNaive:
		if in.Security.Type != SecurityTLS {
			return fmt.Errorf("%s requires tls", in.Protocol)
		}
	case ProtoMTProto:
		if in.Security.Type != "" && in.Security.Type != SecurityNone {
			return fmt.Errorf("mtproto brings its own disguise, leave security off")
		}
		switch in.Options.MTMode {
		case "padded":
		case "faketls", "":
			if in.Options.MTDomain == "" {
				return fmt.Errorf("mtproto needs a cover site for the faketls disguise")
			}
		default:
			return fmt.Errorf("unknown mtproto disguise %q", in.Options.MTMode)
		}
	case ProtoWireGuard:
		if in.Options.WGPrivate == "" {
			return fmt.Errorf("wireguard needs a server key")
		}
		if _, err := WGServerAddress(in.Options.WGSubnet); err != nil {
			return fmt.Errorf("wireguard: %w", err)
		}
	}
	return nil
}

// udpOrTCP says which socket family an inbound binds, so the same port can be shared across both.
func udpOrTCP(in Inbound) string {
	switch in.Protocol {
	case ProtoHysteria2, ProtoTUIC, ProtoWireGuard:
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
