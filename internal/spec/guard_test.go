package spec

import "testing"

func TestCloakOf(t *testing.T) {
	in := Inbound{Tag: "r", Protocol: ProtoVLESS, Port: 443, Transport: Transport{Type: "tcp"},
		Security: Security{Type: SecurityReality, Reality: &Reality{Dest: "127.0.0.1:8443", ServerNames: []string{"me.example.com"}, XVer: 1}}}
	if _, ok := in.CloakOf(); ok {
		t.Fatal("a guard must be off unless enabled")
	}
	in.Options.Guard = &Guard{Enabled: true}
	c, ok := in.CloakOf()
	if !ok || c.Target != "127.0.0.1:8443" || c.SNI != "me.example.com" || c.XVer != 1 || !c.Takeover || !c.Restart || c.Interval != GuardInterval {
		t.Fatalf("got %+v", c)
	}
	zero, off := 0, false
	in.Options.Guard = &Guard{Enabled: true, XVer: &zero, Takeover: &off, Target: "10.0.0.1:443"}
	if c, _ := in.CloakOf(); c.XVer != 0 || c.Takeover || c.Target != "10.0.0.1:443" {
		t.Fatalf("overrides ignored: %+v", c)
	}

	tls := Inbound{Tag: "t", Protocol: ProtoTrojan, Port: 443, Transport: Transport{Type: "tcp"},
		Security: Security{Type: SecurityTLS, Caddy: &Caddy{Domain: "me.example.com"}}, Options: Options{Guard: &Guard{Enabled: true}}}
	if err := tls.validateGuard(); err == nil {
		t.Fatal("plain tls without a target must be refused")
	}
	tls.Options.Guard.Target = "127.0.0.1:8443"
	if c, ok := tls.CloakOf(); !ok || c.SNI != "me.example.com" {
		t.Fatalf("got %+v", c)
	}

	udp := Inbound{Protocol: ProtoHysteria2, Options: Options{Guard: &Guard{Enabled: true, Target: "a:1"}}}
	if _, ok := udp.CloakOf(); ok {
		t.Fatal("udp inbounds cannot be guarded")
	}
}
