package share

import (
	"strings"
	"testing"

	"frostbite/internal/spec"
)

func roundTrip(t *testing.T, in spec.Upstream) spec.Upstream {
	t.Helper()
	link, err := Link(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := ParseLink(link)
	if err != nil {
		t.Fatalf("parse %q: %v", link, err)
	}
	return out
}

func TestRealityRoundTrip(t *testing.T) {
	in := spec.Upstream{
		Name: "de reality", Protocol: spec.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: "5783a3e7-e373-51cd-8642-c83782b807c5",
		Transport: spec.Transport{Type: spec.TransportTCP},
		Security: spec.Security{Type: spec.SecurityReality, Fingerprint: "chrome", Reality: &spec.Reality{
			ServerNames: []string{"example.com"}, PublicKey: "pub", ShortIDs: []string{"ab12"},
		}},
		Options: spec.Options{Flow: "xtls-rprx-vision"},
	}
	out := roundTrip(t, in)
	if out.UUID != in.UUID || out.Options.Flow != in.Options.Flow || out.Security.Reality.PublicKey != "pub" ||
		out.Security.Reality.ShortIDs[0] != "ab12" || out.Name != "de reality" {
		t.Fatalf("lost data: %+v", out)
	}
}

func TestVMessWS(t *testing.T) {
	in := spec.Upstream{
		Name: "cdn", Protocol: spec.ProtoVMess, Address: "cdn.example.com", Port: 443, UUID: "5783a3e7-e373-51cd-8642-c83782b807c5",
		Transport: spec.Transport{Type: spec.TransportWS, Path: "/ws", Host: "cdn.example.com"},
		Security:  spec.Security{Type: spec.SecurityTLS, SNI: "cdn.example.com"},
	}
	out := roundTrip(t, in)
	if out.Transport.Path != "/ws" || out.Security.Type != spec.SecurityTLS || out.Port != 443 {
		t.Fatalf("lost data: %+v", out)
	}
}

func TestShadowsocks2022(t *testing.T) {
	in := spec.Upstream{
		Name: "ss", Protocol: spec.ProtoShadowsocks, Address: "::1", Port: 8388, Password: "abc+/=def",
		Options: spec.Options{Method: "2022-blake3-aes-128-gcm"},
	}
	out := roundTrip(t, in)
	if out.Password != in.Password || out.Options.Method != in.Options.Method || out.Address != "::1" {
		t.Fatalf("lost data: %+v", out)
	}
}

func TestHysteria2AndTUIC(t *testing.T) {
	hy := roundTrip(t, spec.Upstream{
		Name: "hy", Protocol: spec.ProtoHysteria2, Address: "h.example.com", Port: 8443, Password: "p@ss",
		Security: spec.Security{Type: spec.SecurityTLS, SNI: "h.example.com"}, Options: spec.Options{Obfs: "salamander", ObfsPass: "o"},
	})
	if hy.Password != "p@ss" || hy.Options.Obfs != "salamander" {
		t.Fatalf("hy2 lost data: %+v", hy)
	}
	tu := roundTrip(t, spec.Upstream{
		Name: "tu", Protocol: spec.ProtoTUIC, Address: "t.example.com", Port: 8444, UUID: "5783a3e7-e373-51cd-8642-c83782b807c5", Password: "pw",
		Security: spec.Security{Type: spec.SecurityTLS, SNI: "t.example.com"},
	})
	if tu.UUID == "" || tu.Password != "pw" {
		t.Fatalf("tuic lost data: %+v", tu)
	}
}

func TestFormatsRender(t *testing.T) {
	profiles := []spec.Upstream{{
		Name: "p1", Protocol: spec.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: "5783a3e7-e373-51cd-8642-c83782b807c5",
		Security: spec.Security{Type: spec.SecurityReality, Reality: &spec.Reality{ServerNames: []string{"a.com"}, PublicKey: "k", ShortIDs: []string{"ab"}}},
	}, {
		Name: "p2", Protocol: spec.ProtoHysteria2, Address: "h.example.com", Port: 8443, Password: "pw",
		Security: spec.Security{Type: spec.SecurityTLS, SNI: "h.example.com"},
	}}
	for _, f := range Formats {
		body, err := Render(f, profiles, nil)
		if err != nil || len(body) == 0 {
			t.Fatalf("%s: %v", f, err)
		}
	}
	if DetectFormat("clash.meta/1.18") != FormatClash || DetectFormat("sing-box 1.12") != FormatSingbox || DetectFormat("curl") != FormatLinks {
		t.Fatal("user agent detection is off")
	}
}

func TestWireGuardLinkAndConfig(t *testing.T) {
	up := spec.Upstream{
		Name: "wg", Protocol: spec.ProtoWireGuard, Address: "203.0.113.5", Port: 51820, Password: "PRIV+/=",
		Options: spec.Options{WGPublic: "PUB+/=", WGAddress: "10.8.0.5", WGDNS: "1.1.1.1"},
	}
	link, err := Link(up)
	if err != nil || !strings.HasPrefix(link, "wireguard://PRIV%2B%2F%3D@203.0.113.5:51820?") || !strings.Contains(link, "address=10.8.0.5%2F32") {
		t.Fatalf("unexpected link %q (%v)", link, err)
	}
	conf := WGQuick(up, "1.1.1.1")
	for _, want := range []string{"PrivateKey = PRIV+/=", "Address = 10.8.0.5/32", "DNS = 1.1.1.1", "Endpoint = 203.0.113.5:51820", "PublicKey = PUB+/="} {
		if !strings.Contains(conf, want) {
			t.Errorf("config is missing %q:\n%s", want, conf)
		}
	}
}

func TestClientProfilesNeverCarryTheServerKey(t *testing.T) {
	ep := Endpoint{
		Inbound:     spec.Inbound{Tag: "wg", Protocol: spec.ProtoWireGuard, Port: 51820, Options: spec.Options{WGSubnet: "10.8.0.0/16", WGPrivate: "SERVERSECRET", WGPublic: "pub", ServerKey: "ssk"}},
		NodeAddress: "203.0.113.5", NodeName: "n",
	}
	up, err := Upstream(ep, spec.User{ID: 1, Name: "u1", Password: "userkey"})
	if err != nil {
		t.Fatal(err)
	}
	if up.Options.WGPrivate != "" || up.Options.ServerKey != "" || up.Options.WGAddress != "10.8.0.2" {
		t.Fatalf("server secrets leaked or address missing: %+v", up.Options)
	}
}
