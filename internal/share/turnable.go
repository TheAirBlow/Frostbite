package share

import (
	"fmt"
	"net"
	"strconv"

	tconfig "github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/config/providers"
	"github.com/theairblow/turnable/pkg/connection/relay"
	_ "github.com/theairblow/turnable/pkg/init"

	"frostbite/internal/spec"
)

// turnableLink writes the client config Turnable's own client imports, as a turnable:// url.
func turnableLink(u spec.Upstream) (string, error) {
	o := u.Options.TurnableDefaults()
	if len(o.TRoutes) == 0 {
		return "", fmt.Errorf("turnable: no destination")
	}
	server := &relay.ServerConfig{
		ServerConfig: tconfig.ServerConfig{Type: "relay", PlatformID: o.TPlatform, CallID: o.TCallID},
		Proto:        o.TProto, PubKey: o.TPublic, Cloak: "none", PublicIP: u.Address,
		ListenAddr: net.JoinHostPort("0.0.0.0", strconv.Itoa(u.Port)),
	}
	var routes []*providers.Route
	var allowed []string
	for _, r := range o.TRoutes {
		host, port, err := r.Split()
		if err != nil {
			return "", fmt.Errorf("turnable: route %s: %w", r.ID, err)
		}
		route := &providers.Route{ID: r.ID, Address: host, Port: port, Socket: r.Socket, Transport: r.Transport, Encryption: r.Encryption, Name: r.Name}
		if r.IsLocal() {
			route.LocalPort = r.LocalPort
		}
		routes = append(routes, route)
		allowed = append(allowed, r.ID)
	}
	user := &providers.User{UUID: u.UUID, AllowedRoutes: allowed, Type: "relay", Peers: o.TPeers}

	cfg, err := (&relay.Handler{}).GetClientConfig(server, user, routes)
	if err != nil {
		return "", fmt.Errorf("turnable: %w", err)
	}
	// One link carries every route, so it is named after the host rather than the route names Turnable joins.
	if c, ok := cfg.(*relay.ClientConfig); ok && u.Name != "" {
		c.Name = u.Name
	}
	return cfg.ToURL()
}
