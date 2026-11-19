package compose

import (
	"strings"
	"testing"

	"frostbite/internal/db"
	"frostbite/internal/keys"
	"frostbite/internal/spec"
)

// turnableTopology is one node with an xray daemon, a Turnable daemon, and a Turnable inbound whose destinations
// show each kind: one of the panel's inbounds, a plain external destination, and a link written by hand.
func turnableTopology(t *testing.T) (*Topology, db.User) {
	t.Helper()
	pair, err := keys.Turnable()
	if err != nil {
		t.Fatal(err)
	}
	reality := spec.Security{Type: spec.SecurityReality, Reality: &spec.Reality{
		Dest: "www.example.com:443", ServerNames: []string{"www.example.com"}, PrivateKey: "priv", PublicKey: "pub", ShortIDs: []string{"ab"},
	}}
	topo := &Topology{
		Nodes:   map[int64]db.Node{1: {ID: 1, Name: "Frankfurt", Address: "vpn.example.com", Country: "DE", Enabled: true}},
		Daemons: map[int64]db.Daemon{10: {ID: 10, NodeID: 1, Kind: "xray", Enabled: true}, 11: {ID: 11, NodeID: 1, Kind: "turnable", Enabled: true}},
		Inbounds: map[int64]db.Inbound{
			// only reachable through the tunnel
			100: {ID: 100, DaemonID: 10, Tag: "vless-inner", Protocol: spec.ProtoVLESS, Listen: "127.0.0.1", Port: 8443, Transport: spec.Transport{Type: "tcp"}, Security: reality, Enabled: true},
			101: {ID: 101, DaemonID: 11, Tag: "turn", Protocol: spec.ProtoTurnable, Listen: "0.0.0.0", Port: 56000, Enabled: true, Options: spec.Options{
				TCallID: "abc", TPrivate: pair.Private, TPublic: pair.Public,
				TRoutes: []spec.TurnableRouteSpec{
					{ID: "vpn", Name: "Via tunnel", Kind: spec.RouteInbound, InboundID: 100, Socket: "tcp", LocalPort: 10800},
					{ID: "wg", Target: "127.0.0.1:51820", Socket: "udp"},
					{ID: "hand", Kind: spec.RouteCustom, Target: "127.0.0.1:1080", Socket: "tcp", URL: "socks://{user}:{password}@{host}:{port}#{name}", LocalPort: 10801},
				},
			}},
			102: {ID: 102, DaemonID: 10, Tag: "vless-public", Protocol: spec.ProtoVLESS, Listen: "", Port: 443, Transport: spec.Transport{Type: "tcp"}, Security: reality, Enabled: true},
		},
		Hosts:         map[int64][]db.Host{},
		SquadInbounds: map[int64][]int64{1: {100, 101, 102}, 2: {101, 102}},
	}
	return topo, db.User{ID: 5, Username: "alice", Uuid: "11111111-1111-4111-8111-111111111111", Password: "secret"}
}

func TestOrdinaryAppsGetConnectionsToTheLocalPort(t *testing.T) {
	topo, u := turnableTopology(t)
	got := topo.Profiles(u, []int64{1}, ModeStandard)

	var local []Profile
	for _, p := range got {
		if p.Protocol == spec.ProtoTurnable {
			t.Fatal("an ordinary app must not be handed a turnable:// link")
		}
		if p.Via == "turnable-local" {
			local = append(local, p)
		}
	}
	if len(got) != 3 || len(local) != 2 {
		t.Fatalf("want the public inbound plus two local connections, got %d profiles (%d local)", len(got), len(local))
	}

	vpn := local[0]
	if vpn.Protocol != spec.ProtoVLESS || vpn.Address != "127.0.0.1" || vpn.Port != 10800 || vpn.Name != "Via tunnel" {
		t.Fatalf("the inbound route should look like its inbound at the local port: %+v", vpn.Upstream)
	}
	if vpn.Security.Type != spec.SecurityReality || vpn.Security.Reality == nil || vpn.Security.Reality.ServerNames[0] != "www.example.com" {
		t.Fatalf("the settings of the inbound must carry over: %+v", vpn.Security)
	}
	if vpn.UUID == "" {
		t.Fatal("the user needs their credentials on that inbound")
	}

	hand := local[1]
	if hand.Protocol != spec.ProtoSOCKS || hand.Address != "127.0.0.1" || hand.Port != 10801 {
		t.Fatalf("the custom link should be read back into an upstream: %+v", hand.Upstream)
	}
	if !strings.HasPrefix(hand.RawLink, "socks://alice:") || !strings.Contains(hand.RawLink, "@127.0.0.1:10801#") {
		t.Fatalf("placeholders were not filled in: %q", hand.RawLink)
	}
}

func TestTurnableAppsGetOnlyTheTunnel(t *testing.T) {
	topo, u := turnableTopology(t)
	got := topo.Profiles(u, []int64{1}, ModeTurnable)
	if len(got) != 1 || got[0].Protocol != spec.ProtoTurnable || got[0].Via != "turnable" {
		t.Fatalf("got %+v", got)
	}
}

func TestEverythingIsListedForPeople(t *testing.T) {
	topo, u := turnableTopology(t)
	if got := topo.Profiles(u, []int64{1}, ModeAll); len(got) != 4 {
		t.Fatalf("want the public inbound, the tunnel and two local connections, got %d", len(got))
	}
}

func TestNoLocalConnectionWithoutAccessToTheInbound(t *testing.T) {
	topo, u := turnableTopology(t)
	// squad 2 has the tunnel but not the inbound behind it
	for _, p := range topo.Profiles(u, []int64{2}, ModeStandard) {
		if p.Via == "turnable-local" && p.Port == 10800 {
			t.Fatal("a user with no access to the inbound has no credentials for it")
		}
	}
}

func TestRoutesFollowTheInboundTheyLeadTo(t *testing.T) {
	topo, _ := turnableTopology(t)
	in := topo.Inbounds[101]
	moved := topo.Inbounds[100]
	moved.Port = 9999
	topo.Inbounds[100] = moved

	routes := topo.ResolveRoutes(in.Options).TRoutes
	if routes[0].Target != "127.0.0.1:9999" {
		t.Fatalf("the destination should follow the inbound's port, got %q", routes[0].Target)
	}
	if routes[1].Target != "127.0.0.1:51820" {
		t.Fatalf("other destinations are left alone, got %q", routes[1].Target)
	}
	if in.Options.TRoutes[0].Target != "" {
		t.Fatal("resolving must not change the stored routes")
	}
}
