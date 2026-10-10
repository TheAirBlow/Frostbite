// Package share turns inbounds into client profiles, share links and subscription documents.
package share

import (
	"fmt"
	"slices"
	"strings"

	"frostbite/internal/spec"
)

// Host is how an inbound is presented to clients, overriding the server side values.
type Host struct {
	Remark      string
	Address     string
	Port        int
	SNI         string
	Host        string
	Path        string
	ALPN        []string
	Fingerprint string
	Insecure    bool
	Mux         *spec.Mux
	Fragment    *spec.Frag
}

// Endpoint is one reachable way into an inbound.
type Endpoint struct {
	Inbound     spec.Inbound
	Host        Host
	NodeAddress string
	NodeName    string
	Country     string
}

// Upstream builds the client side description of an endpoint for one user.
func Upstream(ep Endpoint, u spec.User) (spec.Upstream, error) {
	in, h := ep.Inbound, ep.Host
	addr := h.Address
	if addr == "" {
		addr = ep.NodeAddress
	}
	if addr == "" {
		return spec.Upstream{}, fmt.Errorf("inbound %s has no address to advertise", in.Tag)
	}
	port := h.Port
	if port == 0 {
		port = in.Port
	}

	up := spec.Upstream{
		Name:      remark(ep, u),
		Protocol:  in.Protocol,
		Address:   addr,
		Port:      port,
		UUID:      u.UUID,
		Password:  u.Password,
		Transport: in.Transport,
		Security:  clientSecurity(in.Security, h),
		Options:   in.Options,
	}
	if in.Protocol == spec.ProtoSOCKS || in.Protocol == spec.ProtoHTTP || in.Protocol == spec.ProtoMixed || in.Protocol == spec.ProtoNaive {
		up.Username = u.Name
	}
	if in.Protocol == spec.ProtoVLESS && up.Options.Flow == "" {
		up.Options.Flow = u.Flow
	}

	if h.Path != "" {
		up.Transport.Path = h.Path
	}
	if h.Host != "" {
		up.Transport.Host = h.Host
	}
	if h.Mux != nil {
		up.Options.Mux = h.Mux
	}
	if h.Fragment != nil {
		up.Options.Fragment = h.Fragment
	}
	if in.Protocol == spec.ProtoWireGuard {
		addr, err := spec.WGAddress(in.Options.WGSubnet, u.ID)
		if err != nil {
			return spec.Upstream{}, err
		}
		up.Options.WGAddress = addr
	}
	// Server secrets must never reach a client.
	up.Options.ServerKey = ""
	up.Options.WGPrivate = ""
	up.Options.TPrivate = ""
	return up, nil
}

// clientSecurity strips server only material and applies host overrides.
func clientSecurity(s spec.Security, h Host) spec.Security {
	out := spec.Security{
		Type: s.Type, SNI: s.SNI, ALPN: s.ALPN, Fingerprint: s.Fingerprint, Insecure: s.Insecure, ECHConfig: s.ECHConfig,
	}
	if s.Reality != nil {
		out.Reality = &spec.Reality{
			ServerNames: s.Reality.ServerNames, PublicKey: s.Reality.PublicKey, ShortIDs: s.Reality.ShortIDs, SpiderX: s.Reality.SpiderX,
		}
	}
	if h.SNI != "" {
		if out.Type == spec.SecurityReality && out.Reality != nil {
			out.Reality.ServerNames = []string{h.SNI}
		} else {
			out.SNI = h.SNI
		}
	}
	if len(h.ALPN) > 0 {
		out.ALPN = slices.Clone(h.ALPN)
	}
	if h.Fingerprint != "" {
		out.Fingerprint = h.Fingerprint
	}
	if h.Insecure {
		out.Insecure = true
	}
	if out.Type == spec.SecurityTLS && out.SNI == "" {
		out.SNI = hostOrAddr(h)
	}
	return out
}

// hostOrAddr picks the best name to present as SNI when none is set.
func hostOrAddr(h Host) string {
	if h.Host != "" {
		return h.Host
	}
	return h.Address
}

// remark renders a host's remark template for one user.
func remark(ep Endpoint, u spec.User) string {
	t := ep.Host.Remark
	if t == "" {
		t = "{node} {protocol}"
	}
	sec := ep.Inbound.Security.Type
	if sec == "" {
		sec = "none"
	}
	return strings.NewReplacer(
		"{node}", ep.NodeName,
		"{country}", ep.Country,
		"{inbound}", ep.Inbound.Tag,
		"{protocol}", ep.Inbound.Protocol,
		"{transport}", ep.Inbound.Transport.Type,
		"{security}", sec,
		"{user}", u.Name,
	).Replace(t)
}
