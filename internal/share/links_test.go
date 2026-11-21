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

func TestNaiveLinkAsksForUDPOverTCP(t *testing.T) {
	link, err := Link(spec.Upstream{Protocol: spec.ProtoNaive, Address: "a.example", Port: 443, Username: "u1", Password: "p@ss", Name: "n", Security: spec.Security{SNI: "pass.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if want := "naive+https://u1:p%40ss@a.example:443?sni=pass.example&uot=1#n"; link != want {
		t.Errorf("got %s, want %s", link, want)
	}
}

func TestClientOptionsRoundTrip(t *testing.T) {
	mux := &spec.Mux{Enabled: true, Protocol: "smux", Concurrency: 16, Padding: true}
	frag := &spec.Frag{Enabled: true, Packets: "tlshello", Length: "50-100", Interval: "5-10"}
	ws := spec.Transport{Type: spec.TransportWS, Path: "/ws", Host: "cdn.example", EarlyData: 2048, Headers: map[string]string{"User-Agent": "x", "X-A": "b"}}
	tls := spec.Security{Type: spec.SecurityTLS, SNI: "cdn.example", Insecure: true, ECHConfig: "AEX+", ALPN: []string{"h2", "http/1.1"}, Fingerprint: "firefox"}

	for _, proto := range []string{spec.ProtoVLESS, spec.ProtoTrojan, spec.ProtoVMess} {
		t.Run(proto, func(t *testing.T) {
			in := spec.Upstream{
				Name: "n", Protocol: proto, Address: "a.example", Port: 443, UUID: "5783a3e7-e373-51cd-8642-c83782b807c5", Password: "pw",
				Transport: ws, Security: tls, Options: spec.Options{Mux: mux, Fragment: frag},
			}
			out := roundTrip(t, in)
			if out.Transport.Path != "/ws" || out.Transport.EarlyData != 2048 || out.Transport.Headers["X-A"] != "b" || out.Transport.Headers["User-Agent"] != "x" {
				t.Errorf("transport: %+v", out.Transport)
			}
			if !out.Security.Insecure || out.Security.SNI != "cdn.example" || len(out.Security.ALPN) != 2 {
				t.Errorf("security: %+v", out.Security)
			}
			if m := out.Options.Mux; m == nil || *m != *mux {
				t.Errorf("mux: %+v", m)
			}
			if f := out.Options.Fragment; f == nil || *f != *frag {
				t.Errorf("fragment: %+v", f)
			}
			if proto != spec.ProtoVMess && out.Security.ECHConfig != "AEX+" {
				t.Errorf("ech: %q", out.Security.ECHConfig)
			}
		})
	}
}

func TestMuxLinkParameters(t *testing.T) {
	up := spec.Upstream{Name: "n", Protocol: spec.ProtoTrojan, Address: "a.example", Port: 443, Password: "pw",
		Security: spec.Security{Type: spec.SecurityTLS}, Options: spec.Options{Mux: &spec.Mux{Enabled: true}}}
	link, _ := Link(up)
	for _, want := range []string{"mux=true", "mux_protocol=h2mux", "muxtype=h2mux"} {
		if !strings.Contains(link, want) {
			t.Errorf("%s is missing %s", link, want)
		}
	}
	up.Options.Mux.Enabled = false
	if link, _ := Link(up); strings.Contains(link, "mux") {
		t.Errorf("mux that is off must not be written, Hiddify would turn it on: %s", link)
	}
}

func TestShadowsocksMux(t *testing.T) {
	in := spec.Upstream{Name: "n", Protocol: spec.ProtoShadowsocks, Address: "a.example", Port: 8388, Password: "pw",
		Options: spec.Options{Method: "2022-blake3-aes-128-gcm", Mux: &spec.Mux{Enabled: true, Protocol: "yamux"}}}
	out := roundTrip(t, in)
	if out.Password != "pw" || out.Options.Mux == nil || out.Options.Mux.Protocol != "yamux" {
		t.Fatalf("got %+v", out)
	}
	in.Options.Mux = nil
	if link, _ := Link(in); strings.Contains(link, "?") {
		t.Errorf("no query without options: %s", link)
	}
}

func TestQUICOptionsRoundTrip(t *testing.T) {
	hy := roundTrip(t, spec.Upstream{Name: "n", Protocol: spec.ProtoHysteria2, Address: "a.example", Port: 443, Password: "pw",
		Security: spec.Security{SNI: "a.example", ECHConfig: "E"}, Options: spec.Options{UpMbps: 50, DownMbps: 200}})
	if hy.Options.UpMbps != 50 || hy.Options.DownMbps != 200 || hy.Security.ECHConfig != "E" {
		t.Errorf("hysteria2: %+v", hy)
	}
	tu := roundTrip(t, spec.Upstream{Name: "n", Protocol: spec.ProtoTUIC, Address: "a.example", Port: 443, UUID: "u", Password: "pw",
		Security: spec.Security{Insecure: true}, Options: spec.Options{ZeroRTT: true, Heartbeat: "10s", CongestCtl: "bbr"}})
	if !tu.Options.ZeroRTT || tu.Options.Heartbeat != "10s" || tu.Options.CongestCtl != "bbr" || !tu.Security.Insecure || tu.Security.ALPN[0] != "h3" {
		t.Errorf("tuic: %+v", tu)
	}
	at := roundTrip(t, spec.Upstream{Name: "n", Protocol: spec.ProtoAnyTLS, Address: "a.example", Port: 443, Password: "pw",
		Security: spec.Security{Fingerprint: "chrome", ALPN: []string{"h2"}}, Options: spec.Options{Fragment: &spec.Frag{Enabled: true}}})
	if at.Security.Fingerprint != "chrome" || at.Security.ALPN[0] != "h2" || at.Options.Fragment == nil || at.Options.Fragment.Packets != "tlshello" {
		t.Errorf("anytls: %+v %+v", at.Security, at.Options.Fragment)
	}
}

func TestHTTPLink(t *testing.T) {
	in := spec.Upstream{Name: "n", Protocol: spec.ProtoHTTP, Address: "a.example", Port: 8443, Username: "u1", Password: "p@ss",
		Security: spec.Security{Type: spec.SecurityTLS, SNI: "a.example"}}
	link, err := Link(in)
	if err != nil || link != "https://u1:p%40ss@a.example:8443?sni=a.example#n" {
		t.Fatalf("got %s, %v", link, err)
	}
	out := roundTrip(t, in)
	if out.Protocol != spec.ProtoHTTP || out.Username != "u1" || out.Password != "p@ss" || out.Security.Type != spec.SecurityTLS {
		t.Fatalf("got %+v", out)
	}
}

func TestEarlyDataKeepsOtherPathQuery(t *testing.T) {
	path, ed := splitEarlyData("/ws?a=1&ed=4096")
	if path != "/ws?a=1" || ed != 4096 {
		t.Fatalf("got %q %d", path, ed)
	}
	if p := earlyDataPath(spec.Transport{Type: spec.TransportWS, Path: "/ws?a=1", EarlyData: 2048}); p != "/ws?a=1&ed=2048" {
		t.Fatalf("got %q", p)
	}
}

func TestHysteria2ClientBandwidthIsTheServerFlipped(t *testing.T) {
	in := spec.Inbound{Tag: "hy", Protocol: spec.ProtoHysteria2, Port: 443, Options: spec.Options{UpMbps: 100, DownMbps: 20}}
	up, err := Upstream(Endpoint{Inbound: in, NodeAddress: "h.example"}, spec.User{Name: "u1", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if up.Options.UpMbps != 20 || up.Options.DownMbps != 100 {
		t.Fatalf("a client sends what the server receives: up %d down %d", up.Options.UpMbps, up.Options.DownMbps)
	}
}
