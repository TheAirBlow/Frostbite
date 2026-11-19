package spec

import (
	"net"
	"strings"
)

// Cloak is the real site an inbound pretends to be, resolved from its guard and its own settings.
type Cloak struct {
	Target   string // host:port
	SNI      string
	XVer     int
	Interval int
	Timeout  int
	Failures int
	GiveUp   int
	Takeover bool
	Restart  bool
}

// CloakOf resolves the guard of an inbound, reporting false when it is off or has nothing to guard.
func (in Inbound) CloakOf() (Cloak, bool) {
	g := in.Options.Guard
	if g == nil || !g.Enabled || in.Network() != "tcp" || in.Protocol == ProtoForward {
		return Cloak{}, false
	}
	c := Cloak{
		Target: g.Target, SNI: g.SNI,
		Interval: orDefault(g.Interval, GuardInterval), Timeout: orDefault(g.Timeout, GuardTimeout), Failures: orDefault(g.Failures, GuardFailures),
		GiveUp:   orDefault(g.GiveUp, GuardGiveUp),
		Takeover: g.Takeover == nil || *g.Takeover, Restart: g.Restart == nil || *g.Restart,
	}

	sec := in.Security
	var xver int
	switch {
	case sec.Type == SecurityReality && sec.Reality != nil:
		if c.Target == "" {
			c.Target = sec.Reality.Dest
		}
		if c.SNI == "" && len(sec.Reality.ServerNames) > 0 {
			c.SNI = sec.Reality.ServerNames[0]
		}
		xver = sec.Reality.XVer
	case in.Protocol == ProtoShadowTLS:
		if c.Target == "" {
			c.Target = in.Options.Handshake
		}
	case in.Protocol == ProtoMTProto && in.Options.MTDomain != "":
		if c.Target == "" {
			c.Target = net.JoinHostPort(in.Options.MTDomain, "443")
		}
		if c.SNI == "" {
			c.SNI = in.Options.MTDomain
		}
	case sec.Type == SecurityTLS && c.SNI == "":
		switch {
		case sec.SNI != "":
			c.SNI = sec.SNI
		case sec.ACME != nil:
			c.SNI = sec.ACME.Domain
		case sec.Caddy != nil:
			c.SNI = sec.Caddy.Domain
		}
	}
	if g.XVer != nil {
		xver = *g.XVer
	}
	c.XVer = xver
	if c.SNI == "" {
		if host, _, err := net.SplitHostPort(c.Target); err == nil && net.ParseIP(host) == nil {
			c.SNI = host
		}
	}
	if c.Target == "" {
		return Cloak{}, false
	}
	return c, true
}

func orDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// validateGuard checks the guard settings of an inbound.
func (in Inbound) validateGuard() error {
	g := in.Options.Guard
	if g == nil || !g.Enabled {
		return nil
	}
	if in.Network() != "tcp" || in.Protocol == ProtoForward {
		return Invalid("options.guard.enabled", "only tcp inbounds that cloak as a real site can be guarded")
	}
	if g.Target != "" {
		if _, _, err := net.SplitHostPort(g.Target); err != nil {
			return Invalid("options.guard.target", "the target must look like host:port")
		}
	}
	if g.SNI != "" && strings.ContainsAny(g.SNI, " /:") {
		return Invalid("options.guard.sni", "not a valid server name")
	}
	if g.XVer != nil && (*g.XVer < 0 || *g.XVer > 2) {
		return Invalid("options.guard.xver", "the PROXY header version must be 0, 1 or 2")
	}
	if g.Interval < 0 || g.Interval > 3600 {
		return Invalid("options.guard.interval", "use 1 to 3600 seconds")
	}
	if g.Timeout < 0 || g.Timeout > 60 {
		return Invalid("options.guard.timeout", "use 1 to 60 seconds")
	}
	if g.Failures < 0 || g.Failures > 100 {
		return Invalid("options.guard.failures", "use 1 to 100")
	}
	if g.GiveUp < 0 || g.GiveUp > 100 {
		return Invalid("options.guard.give_up", "use 1 to 100")
	}
	if _, ok := in.CloakOf(); !ok {
		return Invalid("options.guard.target", "this inbound has no real site to fall back to, set a target")
	}
	return nil
}
