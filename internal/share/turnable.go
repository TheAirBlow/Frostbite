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
	host, port, err := o.TurnableTarget()
	if err != nil {
		return "", err
	}
	server := &relay.ServerConfig{
		ServerConfig: tconfig.ServerConfig{Type: "relay", PlatformID: o.TPlatform, CallID: o.TCallID},
		Proto:        o.TProto, PubKey: o.TPublic, Cloak: "none", PublicIP: u.Address,
		ListenAddr: net.JoinHostPort("0.0.0.0", strconv.Itoa(u.Port)),
	}
	route := &providers.Route{
		ID: spec.TurnableRoute, Address: host, Port: port, Socket: o.TSocket,
		Transport: o.TTransport, Encryption: o.TEncryption, Name: u.Name,
	}
	user := &providers.User{UUID: u.UUID, AllowedRoutes: []string{route.ID}, Type: "relay", Peers: o.TPeers}

	cfg, err := (&relay.Handler{}).GetClientConfig(server, user, []*providers.Route{route})
	if err != nil {
		return "", fmt.Errorf("turnable: %w", err)
	}
	return cfg.ToURL()
}
