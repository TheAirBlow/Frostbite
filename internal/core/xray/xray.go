// Package xray renders specs into xray-core configs.
package xray

import (
	"encoding/json"
	"fmt"
	"strings"

	"frostbite/internal/core"
	"frostbite/internal/spec"
)

// APIPort is where the agent reaches xray's gRPC API, bound to loopback only.
const APIPort = 10085

// APITag is the tag of the internal api inbound.
const APITag = "api"

func init() {
	core.Register(core.Descriptor{
		Kind:        "xray",
		DisplayName: "Xray",
		Caps: core.Capabilities{
			Protocols:  []string{spec.ProtoVLESS, spec.ProtoVMess, spec.ProtoTrojan, spec.ProtoShadowsocks, spec.ProtoSOCKS, spec.ProtoHTTP, spec.ProtoForward},
			Transports: []string{spec.TransportTCP, spec.TransportWS, spec.TransportGRPC, spec.TransportHTTPUpgrade, spec.TransportXHTTP, spec.TransportKCP},
			Securities: []string{spec.SecurityNone, spec.SecurityTLS, spec.SecurityReality},
			Outbounds:  []string{spec.OutDirect, spec.OutBlock, spec.OutProxy, spec.OutWarp},
			HotUsers:   true,
		},
		Render: Render,
	})
}

// Render builds the full xray config for d.
func Render(d spec.Daemon) ([]byte, error) {
	cfg := map[string]any{
		"log": map[string]any{"loglevel": logLevel(d.Log.Level)},
		"api": map[string]any{"tag": APITag, "services": []string{"HandlerService", "StatsService"}},
		"policy": map[string]any{
			"levels": map[string]any{"0": map[string]any{
				"statsUserUplink": true, "statsUserDownlink": true, "statsUserOnline": true,
			}},
			"system": map[string]any{"statsInboundUplink": true, "statsInboundDownlink": true},
		},
	}
	if dns := renderDNS(d.DNS); dns != nil {
		cfg["dns"] = dns
	}

	inbounds := []any{map[string]any{
		"tag": APITag, "listen": "127.0.0.1", "port": APIPort, "protocol": "dokodemo-door",
		"settings": map[string]any{"address": "127.0.0.1"},
	}}
	for _, in := range d.Inbounds {
		m, err := Inbound(in)
		if err != nil {
			return nil, fmt.Errorf("inbound %s: %w", in.Tag, err)
		}
		if err := core.ApplyPatch(m, in.RawPatch); err != nil {
			return nil, fmt.Errorf("inbound %s: %w", in.Tag, err)
		}
		inbounds = append(inbounds, m)
	}
	cfg["inbounds"] = inbounds

	outs := core.Ordered(d.Outbounds, func(o spec.Outbound) string { return o.Tag }, d.Final)
	if len(outs) == 0 {
		outs = []spec.Outbound{{Tag: "direct", Kind: spec.OutDirect}}
	}
	var outbounds []any
	for _, o := range outs {
		m, err := Outbound(o)
		if err != nil {
			return nil, fmt.Errorf("outbound %s: %w", o.Tag, err)
		}
		outbounds = append(outbounds, m)
	}
	cfg["outbounds"] = outbounds

	rules := []any{map[string]any{"type": "field", "inboundTag": []string{APITag}, "outboundTag": APITag}}
	for _, r := range d.Rules {
		rules = append(rules, renderRule(r))
	}
	cfg["routing"] = map[string]any{"domainStrategy": "AsIs", "rules": rules}

	if err := core.ApplyPatch(cfg, d.RawPatch); err != nil {
		return nil, err
	}
	core.Prune(cfg)
	cfg["stats"] = map[string]any{} // xray wants the key present even when empty
	return json.MarshalIndent(cfg, "", "  ")
}

// logLevel maps the neutral level to xray's names.
func logLevel(l string) string {
	switch l {
	case "":
		return "warning"
	case "none":
		return "none"
	}
	return l
}

// renderDNS builds xray's dns block, or nil when no servers are set.
func renderDNS(d spec.DNS) map[string]any {
	if len(d.Servers) == 0 {
		return nil
	}
	servers := make([]any, len(d.Servers))
	for i, s := range d.Servers {
		servers[i] = s
	}
	q := "UseIP"
	switch d.Strategy {
	case "prefer_ipv4", "ipv4_only":
		q = "UseIPv4"
	case "prefer_ipv6", "ipv6_only":
		q = "UseIPv6"
	}
	return map[string]any{"servers": servers, "queryStrategy": q}
}

// renderRule builds one xray routing rule.
func renderRule(r spec.Rule) map[string]any {
	var domains []string
	for _, v := range r.Domain {
		domains = append(domains, "full:"+v)
	}
	for _, v := range r.DomainSuffix {
		domains = append(domains, "domain:"+v)
	}
	for _, v := range r.DomainKw {
		domains = append(domains, "keyword:"+v)
	}
	for _, v := range r.GeoSite {
		domains = append(domains, "geosite:"+v)
	}
	ips := append([]string{}, r.IPCIDR...)
	for _, v := range r.GeoIP {
		ips = append(ips, "geoip:"+v)
	}
	return map[string]any{
		"type":        "field",
		"inboundTag":  r.InboundTags,
		"user":        r.Users,
		"domain":      domains,
		"ip":          ips,
		"port":        strings.Join(r.Port, ","),
		"network":     r.Network,
		"protocol":    r.Protocol,
		"outboundTag": r.Outbound,
	}
}
