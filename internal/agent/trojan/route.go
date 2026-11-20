package trojan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	coretrojan "frostbite/internal/core/trojan"
	"frostbite/internal/spec"
)

const dialTimeout = 10 * time.Second

var errBlocked = errors.New("blocked by a rule")

// router picks the outbound for a destination and dials it.
type router struct {
	rules    []rule
	outs     map[string]outbound
	final    outbound
	resolver *net.Resolver
	strategy string
}

type outbound struct {
	tag, kind, iface, strategy string
}

// rule is a routing rule ready to match. A rule matches when every condition it sets does.
type rule struct {
	inbounds, users, domains []string
	suffixes, keywords       []string
	cidrs                    []netip.Prefix
	ports                    [][2]uint16
	network                  string
	out                      outbound
}

// target is one connection to route.
type target struct {
	inbound, user string
	network       string // tcp or udp
	dst           addr
	sniffed       string // a server name read from the payload
}

func newRouter(cfg coretrojan.Config) (*router, error) {
	r := &router{outs: map[string]outbound{}, strategy: cfg.DNS.Strategy, resolver: net.DefaultResolver}
	for _, o := range cfg.Outbounds {
		r.outs[o.Tag] = outbound{tag: o.Tag, kind: o.Kind, iface: o.Interface, strategy: o.Strategy}
	}
	final, ok := r.outs[cfg.Final]
	if !ok {
		return nil, fmt.Errorf("final outbound %q does not exist", cfg.Final)
	}
	r.final = final
	for i, cr := range cfg.Rules {
		out, ok := r.outs[cr.Outbound]
		if !ok {
			return nil, fmt.Errorf("rule %d: unknown outbound %q", i+1, cr.Outbound)
		}
		ru := rule{
			inbounds: cr.Inbounds, users: cr.Users, network: cr.Network, out: out,
			domains: lower(cr.Domain), keywords: lower(cr.DomainKw),
		}
		for _, s := range cr.DomainSuffix {
			ru.suffixes = append(ru.suffixes, strings.TrimPrefix(strings.ToLower(s), "."))
		}
		for _, c := range cr.IPCIDR {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				a, aerr := netip.ParseAddr(c)
				if aerr != nil {
					return nil, fmt.Errorf("rule %d: %q is not an address or range", i+1, c)
				}
				p = netip.PrefixFrom(a, a.BitLen())
			}
			ru.cidrs = append(ru.cidrs, p.Masked())
		}
		for _, p := range cr.Port {
			for _, part := range strings.Split(p, ",") {
				pr, err := portRange(part)
				if err != nil {
					return nil, fmt.Errorf("rule %d: %w", i+1, err)
				}
				ru.ports = append(ru.ports, pr)
			}
		}
		r.rules = append(r.rules, ru)
	}
	if len(cfg.DNS.Servers) > 0 {
		servers := cfg.DNS.Servers
		var next atomic.Uint32
		r.resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, network, servers[int(next.Add(1))%len(servers)])
		}}
	}
	return r, nil
}

func lower(l []string) []string {
	out := make([]string, len(l))
	for i, s := range l {
		out[i] = strings.ToLower(s)
	}
	return out
}

// portRange parses 443 or 1000-2000.
func portRange(s string) ([2]uint16, error) {
	s = strings.TrimSpace(s)
	lo, hi, isRange := strings.Cut(s, "-")
	a, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	if err != nil {
		return [2]uint16{}, fmt.Errorf("%q is not a port or range", s)
	}
	b := a
	if isRange {
		if b, err = strconv.ParseUint(strings.TrimSpace(hi), 10, 16); err != nil || b < a {
			return [2]uint16{}, fmt.Errorf("%q is not a port or range", s)
		}
	}
	return [2]uint16{uint16(a), uint16(b)}, nil
}

// route picks the outbound for t. Rules on addresses resolve a name only when one is about to be checked.
func (r *router) route(ctx context.Context, t target) outbound {
	name := t.dst.host
	if t.sniffed != "" {
		name = t.sniffed
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	var resolved []netip.Addr
	var looked bool
	for _, ru := range r.rules {
		if len(ru.inbounds) > 0 && !slices.Contains(ru.inbounds, t.inbound) {
			continue
		}
		if len(ru.users) > 0 && !slices.Contains(ru.users, t.user) {
			continue
		}
		if ru.network != "" && !slices.Contains(strings.Split(ru.network, ","), t.network) {
			continue
		}
		if len(ru.ports) > 0 && !slices.ContainsFunc(ru.ports, func(p [2]uint16) bool { return t.dst.port >= p[0] && t.dst.port <= p[1] }) {
			continue
		}
		// names and ranges both describe the destination, so a rule with both matches either
		hasName := len(ru.domains)+len(ru.suffixes)+len(ru.keywords) > 0
		if hasName || len(ru.cidrs) > 0 {
			hit := hasName && name != "" && ru.matchName(name)
			if !hit && len(ru.cidrs) > 0 {
				ips := []netip.Addr{t.dst.ip}
				if !t.dst.ip.IsValid() {
					if !looked {
						lctx, cancel := context.WithTimeout(ctx, dialTimeout)
						resolved, _ = r.resolver.LookupNetIP(lctx, "ip", t.dst.host)
						cancel()
						looked = true
					}
					ips = resolved
				}
				hit = slices.ContainsFunc(ips, func(ip netip.Addr) bool {
					return slices.ContainsFunc(ru.cidrs, func(p netip.Prefix) bool { return p.Contains(ip.Unmap()) })
				})
			}
			if !hit {
				continue
			}
		}
		return ru.out
	}
	return r.final
}

func (ru rule) matchName(name string) bool {
	if slices.Contains(ru.domains, name) {
		return true
	}
	for _, s := range ru.suffixes {
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	for _, k := range ru.keywords {
		if strings.Contains(name, k) {
			return true
		}
	}
	return false
}

// lookup resolves dst to the addresses worth trying, in the order the strategy of out asks for.
func (r *router) lookup(ctx context.Context, out outbound, dst addr) ([]netip.Addr, error) {
	if dst.ip.IsValid() {
		return []netip.Addr{dst.ip}, nil
	}
	ips, err := r.resolver.LookupNetIP(ctx, "ip", dst.host)
	if err != nil {
		return nil, err
	}
	strategy := out.strategy
	if strategy == "" {
		strategy = r.strategy
	}
	var v4, v6 []netip.Addr
	for _, ip := range ips {
		if ip = ip.Unmap(); ip.Is4() {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	switch strategy {
	case "prefer_ipv4":
		ips = append(v4, v6...)
	case "prefer_ipv6":
		ips = append(v6, v4...)
	case "ipv4_only":
		ips = v4
	case "ipv6_only":
		ips = v6
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s has no address the %s strategy allows", dst.host, strategy)
	}
	return ips, nil
}

// dial opens a TCP connection to dst through out.
func (r *router) dial(ctx context.Context, out outbound, dst addr) (net.Conn, error) {
	if out.kind == spec.OutBlock {
		return nil, errBlocked
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	ips, err := r.lookup(ctx, out, dst)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{KeepAlive: 30 * time.Second, Control: bindControl(out.iface)}
	var errs []error
	for _, ip := range ips {
		c, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(ip, dst.port).String())
		if err == nil {
			return c, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

// listenUDP opens the socket UDP packets leave through out.
func (r *router) listenUDP(out outbound) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: bindControl(out.iface)}
	pc, err := lc.ListenPacket(context.Background(), "udp", ":0")
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}
