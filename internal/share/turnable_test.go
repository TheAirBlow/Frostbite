package share

import (
	"strings"
	"testing"

	tconfig "github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/connection/relay"

	"frostbite/internal/keys"
	"frostbite/internal/spec"
)

func TestTurnableLinkRoundTripsThroughTurnablesOwnParser(t *testing.T) {
	pair, err := keys.Turnable()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := spec.CredentialsFor(spec.ProtoTurnable, "", "00000000-0000-4000-8000-000000000001", "secret")
	in := spec.Inbound{
		Tag: "t", Protocol: spec.ProtoTurnable, Listen: "0.0.0.0", Port: 56000,
		Options: spec.Options{TCallID: "abc123", TTarget: "127.0.0.1:51820", TSocket: "udp", TPrivate: pair.Private, TPublic: pair.Public}.TurnableDefaults(),
	}
	up, err := Upstream(Endpoint{Inbound: in, NodeAddress: "203.0.113.5"}, spec.User{Name: "alice", UUID: id})
	if err != nil {
		t.Fatal(err)
	}
	if up.Options.TPrivate != "" {
		t.Fatal("the server's private key must never reach a client")
	}

	link, err := Link(up)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(link, "turnable://") {
		t.Fatalf("unexpected link %q", link)
	}
	if strings.Contains(link, pair.Private) {
		t.Fatal("the link carries the private key")
	}

	parsed, err := tconfig.ParseClientConfig([]byte(link))
	if err != nil {
		t.Fatalf("turnable cannot read our link: %v", err)
	}
	cfg, ok := parsed.(*relay.ClientConfig)
	if !ok {
		t.Fatalf("unexpected config type %T", parsed)
	}
	if cfg.UserUUID != id || cfg.CallID != "abc123" || cfg.Gateway != "203.0.113.5:56000" || cfg.PubKey != pair.Public {
		t.Fatalf("the link lost something: %+v", cfg)
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0].RouteID != spec.TurnableRoute || cfg.Routes[0].Socket != "udp" {
		t.Fatalf("route is wrong: %+v", cfg.Routes)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the config does not validate: %v", err)
	}
}

func TestTurnableLinkCarriesEveryRoute(t *testing.T) {
	pair, err := keys.Turnable()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := spec.CredentialsFor(spec.ProtoTurnable, "", "00000000-0000-4000-8000-000000000002", "secret")
	in := spec.Inbound{
		Tag: "t", Protocol: spec.ProtoTurnable, Listen: "0.0.0.0", Port: 56000,
		Options: spec.Options{
			TCallID: "abc123", TPrivate: pair.Private, TPublic: pair.Public,
			TRoutes: []spec.TurnableRouteSpec{
				{ID: "wg", Name: "WireGuard", Target: "127.0.0.1:51820", Socket: "udp"},
				{ID: "web", Name: "Web", Target: "127.0.0.1:8443", Socket: "tcp"},
			},
		}.TurnableDefaults(),
	}
	up, err := Upstream(Endpoint{Inbound: in, NodeAddress: "203.0.113.5"}, spec.User{Name: "alice", UUID: id})
	if err != nil {
		t.Fatal(err)
	}
	link, err := Link(up)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := tconfig.ParseClientConfig([]byte(link))
	if err != nil {
		t.Fatal(err)
	}
	cfg := parsed.(*relay.ClientConfig)
	if len(cfg.Routes) != 2 || cfg.Routes[0].RouteID != "wg" || cfg.Routes[1].RouteID != "web" || cfg.Routes[1].Socket != "tcp" {
		t.Fatalf("routes lost on the way: %+v", cfg.Routes)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}
