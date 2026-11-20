package trojan

import (
	"encoding/json"
	"strings"
	"testing"

	"frostbite/internal/spec"
)

func daemon(o spec.Options) spec.Daemon {
	return spec.Daemon{
		Kind: "trojan",
		Inbounds: []spec.Inbound{{
			Tag: "t1", Protocol: spec.ProtoTrojan, Listen: "127.0.0.1", Port: 30001,
			Security: spec.Security{Type: spec.SecurityTLS, CertPath: "/c.pem", KeyPath: "/k.pem"},
			Options:  o, Users: []spec.User{{Name: "u1", Password: "secret-password"}},
		}},
		Outbounds: []spec.Outbound{{Tag: "direct", Kind: spec.OutDirect}, {Tag: "block", Kind: spec.OutBlock}, {Tag: "warp", Kind: spec.OutWarp}},
		Final:     "direct",
	}
}

func render(t *testing.T, d spec.Daemon) (Config, string) {
	t.Helper()
	raw, err := Render(d)
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg, string(raw)
}

func TestRenderKeepsUsersOut(t *testing.T) {
	cfg, text := render(t, daemon(spec.Options{TJDest: "127.0.0.1:80"}))
	if strings.Contains(text, "secret-password") || strings.Contains(text, "u1") {
		t.Fatal("users ended up in the config")
	}
	in := cfg.Inbounds[0]
	if in.Listen != "127.0.0.1:30001" || in.Site.Dest != "127.0.0.1:80" || in.UDPTimeout != spec.TrojanUDPTimeout {
		t.Fatalf("inbound: %+v", in)
	}
	if !in.TCP.NoDelay || !in.TCP.KeepAlive {
		t.Fatalf("tcp defaults: %+v", in.TCP)
	}
}

func TestRenderALPNFollowsTheSite(t *testing.T) {
	cfg, _ := render(t, daemon(spec.Options{TJDest: "127.0.0.1:80"}))
	if got := strings.Join(cfg.Inbounds[0].TLS.ALPN, ","); got != "http/1.1" {
		t.Errorf("raw site: %s", got)
	}
	cfg, _ = render(t, daemon(spec.Options{TJDest: "127.0.0.1:80", TJIPHeader: "X-Real-IP"}))
	if got := strings.Join(cfg.Inbounds[0].TLS.ALPN, ","); got != "h2,http/1.1" {
		t.Errorf("http site: %s", got)
	}
	d := daemon(spec.Options{TJDest: "127.0.0.1:80"})
	d.Inbounds[0].Security.ALPN = []string{"h2"}
	cfg, _ = render(t, d)
	if got := strings.Join(cfg.Inbounds[0].TLS.ALPN, ","); got != "h2" {
		t.Errorf("explicit: %s", got)
	}
}

func TestRenderSiteSettings(t *testing.T) {
	cfg, _ := render(t, daemon(spec.Options{
		TJDest: "site:443", TJTLS: true, TJSNI: "site.example", TJSkip: true, TJProxy: "v2",
		TJByALPN: map[string]string{"h2": "127.0.0.1:81"}, TJPlain: spec.TrojanPlainRedirect,
		TJNagle: true, TJNoAlive: true, TJReuse: true, TJFastOpen: true, TJUDPIdle: 5,
	}))
	in := cfg.Inbounds[0]
	s := in.Site
	if !s.TLS || s.SNI != "site.example" || !s.Insecure || s.Proxy != 2 || s.ByALPN["h2"] != "127.0.0.1:81" || s.HTTP() {
		t.Fatalf("site: %+v", s)
	}
	if in.Plain != spec.TrojanPlainRedirect || in.UDPTimeout != 5 {
		t.Fatalf("inbound: %+v", in)
	}
	if in.TCP.NoDelay || in.TCP.KeepAlive || !in.TCP.ReusePort || !in.TCP.FastOpen {
		t.Fatalf("tcp: %+v", in.TCP)
	}
}

func TestRenderRules(t *testing.T) {
	d := daemon(spec.Options{TJDest: "127.0.0.1:80"})
	d.DNS = spec.DNS{Servers: []string{"1.1.1.1", "https://dns.example/dns-query", "9.9.9.9:5353"}, Strategy: "ipv4_only"}
	d.Rules = []spec.Rule{
		{GeoSite: []string{"category-ads-all"}, Outbound: "block"},
		{Domain: []string{"a.example"}, Outbound: "warp"},
		{IPCIDR: []string{"10.0.0.0/8"}, Outbound: "block"},
	}
	cfg, _ := render(t, d)
	if len(cfg.Rules) != 1 || cfg.Rules[0].IPCIDR[0] != "10.0.0.0/8" {
		t.Fatalf("rules: %+v", cfg.Rules)
	}
	if strings.Join(cfg.DNS.Servers, " ") != "1.1.1.1:53 9.9.9.9:5353" || cfg.DNS.Strategy != "ipv4_only" {
		t.Fatalf("dns: %+v", cfg.DNS)
	}
	for _, o := range cfg.Outbounds {
		if o.Kind == spec.OutWarp {
			t.Fatal("warp outbound kept")
		}
	}

	d.Final = "warp"
	if _, err := Render(d); err == nil {
		t.Fatal("a final outbound the daemon can't use was accepted")
	}
}

func TestRenderPatches(t *testing.T) {
	d := daemon(spec.Options{TJDest: "127.0.0.1:80"})
	d.Inbounds[0].RawPatch = json.RawMessage(`{"plain":"nginx","tls":{"min_version":"1.3"}}`)
	d.RawPatch = json.RawMessage(`{"log_level":"debug"}`)
	cfg, _ := render(t, d)
	in := cfg.Inbounds[0]
	if in.Plain != "nginx" || in.TLS.MinTLS != "1.3" || in.TLS.Cert != "/c.pem" || cfg.LogLevel != "debug" {
		t.Fatalf("patched: %+v %s", in, cfg.LogLevel)
	}
}
