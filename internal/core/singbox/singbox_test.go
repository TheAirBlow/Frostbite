package singbox

import (
	"encoding/json"
	"testing"

	"frostbite/internal/spec"
)

func TestRenderHysteriaAndBlockRule(t *testing.T) {
	d := spec.Daemon{
		Kind: "singbox",
		DNS:  spec.DNS{Servers: []string{"1.1.1.1", "tls://dns.google"}},
		Inbounds: []spec.Inbound{{
			Tag: "hy2", Protocol: spec.ProtoHysteria2, Port: 8443,
			Security: spec.Security{Type: spec.SecurityTLS, SNI: "a.example", CertPath: "/c.pem", KeyPath: "/k.pem"},
			Options:  spec.Options{Obfs: "salamander", ObfsPass: "pw"},
			Sniffing: spec.Sniffing{Enabled: true},
			Users:    []spec.User{{ID: 1, Name: "u1", Password: "secret"}},
		}},
		Outbounds: []spec.Outbound{{Tag: "direct", Kind: spec.OutDirect}, {Tag: "block", Kind: spec.OutBlock}},
		Rules:     []spec.Rule{{GeoIP: []string{"cn"}, Outbound: "block"}},
		Final:     "direct",
	}
	raw, err := Render(d)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}

	route := cfg["route"].(map[string]any)
	rules := route["rules"].([]any)
	if rules[0].(map[string]any)["action"] != "sniff" {
		t.Fatal("sniff action should come first")
	}
	if rules[1].(map[string]any)["action"] != "reject" {
		t.Fatal("rules pointing at a block outbound should become reject")
	}
	if len(route["rule_set"].([]any)) != 1 {
		t.Fatal("geoip rule set missing")
	}
	for _, o := range cfg["outbounds"].([]any) {
		if o.(map[string]any)["type"] == "block" {
			t.Fatal("block outbound should not be emitted")
		}
	}
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	if in["obfs"].(map[string]any)["type"] != "salamander" {
		t.Fatal("obfs missing")
	}
	dns := cfg["dns"].(map[string]any)["servers"].([]any)[1].(map[string]any)
	if dns["type"] != "tls" || dns["server"] != "dns.google" {
		t.Fatalf("dns url parsed wrong: %v", dns)
	}
}

func TestXHTTPRejected(t *testing.T) {
	c := Capabilities()
	for _, tr := range c.Transports {
		if tr == spec.TransportXHTTP {
			t.Fatal("sing-box has no xhttp")
		}
	}
}

func TestWireGuardBecomesAnEndpointWithOnePeerPerUser(t *testing.T) {
	_, k1 := spec.CredentialsFor(spec.ProtoWireGuard, "", "", "one")
	_, k2 := spec.CredentialsFor(spec.ProtoWireGuard, "", "", "two")
	d := spec.Daemon{
		Kind: "singbox",
		Inbounds: []spec.Inbound{{
			Tag: "wg", Protocol: spec.ProtoWireGuard, Port: 51820, Sniffing: spec.Sniffing{Enabled: true},
			Options: spec.Options{WGSubnet: "10.8.0.0/16", WGPrivate: "d1lQ+Or/FLUKXIVxeYog1CJchTiMbYABQjZmh4E76pc="},
			Users:   []spec.User{{ID: 1, Name: "u1", Password: k1}, {ID: 2, Name: "u2", Password: k2}},
		}},
		Outbounds: []spec.Outbound{{Tag: "direct", Kind: spec.OutDirect}},
		Final:     "direct",
	}
	raw, err := Render(d)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["inbounds"] != nil {
		t.Fatal("wireguard is not an inbound in sing-box")
	}
	ep := cfg["endpoints"].([]any)[0].(map[string]any)
	peers := ep["peers"].([]any)
	if len(peers) != 2 || peers[1].(map[string]any)["allowed_ips"].([]any)[0] != "10.8.0.3/32" {
		t.Fatalf("each user gets a peer limited to their own address: %v", peers)
	}
	if ep["address"].([]any)[0] != "10.8.0.1/16" {
		t.Fatalf("server address wrong: %v", ep["address"])
	}
}
