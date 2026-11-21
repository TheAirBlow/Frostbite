package naive

import (
	"encoding/json"
	"strings"
	"testing"

	"frostbite/internal/spec"
)

func daemon(o spec.Options) spec.Daemon {
	return spec.Daemon{
		Kind: "naive",
		Inbounds: []spec.Inbound{{
			Tag: "n1", Protocol: spec.ProtoNaive, Listen: "127.0.0.1", Port: 30001,
			Security: spec.Security{Type: spec.SecurityTLS, CertPath: "/c/fullchain.pem", KeyPath: "/c/privkey.pem"},
			Options:  o,
			Users:    []spec.User{{Name: "u1", Password: "secret-password"}},
		}},
		Outbounds: []spec.Outbound{{Tag: "direct", Kind: spec.OutDirect}, {Tag: "block", Kind: spec.OutBlock}},
	}
}

// render returns the site handler and the whole text of the config.
func render(t *testing.T, d spec.Daemon) (site map[string]any, text string) {
	t.Helper()
	raw, err := Render(d)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	srv := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["n1"].(map[string]any)
	routes := srv["routes"].([]any)
	handlers := routes[1].(map[string]any)["handle"].([]any)
	return handlers[1].(map[string]any), string(raw)
}

func TestUsersStayOutOfTheConfig(t *testing.T) {
	_, text := render(t, daemon(spec.Options{NaiveDest: "127.0.0.1:8443"}))
	if strings.Contains(text, "secret-password") || strings.Contains(text, `"u1"`) {
		t.Error("users are in the config, so every change of users would reload it")
	}
}

func TestSiteHeaders(t *testing.T) {
	cases := []struct {
		name   string
		header string
		set    string // the header the address goes in, empty for none
	}{
		{"default", "", "X-Forwarded-For"},
		{"custom", "X-Real-IP", "X-Real-IP"},
		{"off", spec.NaiveNoHeader, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			site, _ := render(t, daemon(spec.Options{NaiveDest: "127.0.0.1:8443", NaiveHeader: c.header}))
			req := site["headers"].(map[string]any)["request"].(map[string]any)
			set, _ := req["set"].(map[string]any)
			if c.set == "" && len(set) != 1 {
				t.Errorf("set %v, want no header", set)
			}
			if c.set != "" && set[c.set] == nil {
				t.Errorf("set %v, want %s", set, c.set)
			}
			del := req["delete"].([]any)
			deletesXFF := false
			for _, h := range del {
				if h == "X-Forwarded-For" {
					deletesXFF = true
				}
			}
			if want := c.set != "X-Forwarded-For"; deletesXFF != want {
				t.Errorf("deletes X-Forwarded-For = %v, want %v", deletesXFF, want)
			}
		})
	}
}

func TestSiteTransport(t *testing.T) {
	site, _ := render(t, daemon(spec.Options{NaiveDest: "127.0.0.1:8443", NaiveTLS: true, NaiveProxy: "v2", NaiveSkip: true}))
	tr := site["transport"].(map[string]any)
	if tr["proxy_protocol"] != "v2" {
		t.Errorf("proxy_protocol = %v", tr["proxy_protocol"])
	}
	tls := tr["tls"].(map[string]any)
	if tls["server_name"] != "{http.request.host}" || tls["insecure_skip_verify"] != true {
		t.Errorf("tls = %v", tls)
	}

	site, _ = render(t, daemon(spec.Options{NaiveDest: "127.0.0.1:80"}))
	tr = site["transport"].(map[string]any)
	if tr["proxy_protocol"] != nil || tr["tls"] != nil {
		t.Errorf("plain site got %v", tr)
	}
}

func TestEdgeHeaderIsAccepted(t *testing.T) {
	d := daemon(spec.Options{NaiveDest: "127.0.0.1:8443"})
	_, text := render(t, d)
	if strings.Contains(text, "proxy_protocol") {
		t.Error("PROXY header read without an edge")
	}
	d.Inbounds[0].Options.AcceptProxy = true
	_, text = render(t, d)
	if !strings.Contains(text, `"wrapper": "proxy_protocol"`) {
		t.Error("an inbound behind the edge does not read its PROXY header")
	}
}

func TestRulesGoToTheEgress(t *testing.T) {
	d := daemon(spec.Options{NaiveDest: "127.0.0.1:8443"})
	d.Rules = []spec.Rule{
		{GeoSite: []string{"category-ads-all"}, Outbound: "block"},
		{Users: []string{"u1"}, Domain: []string{"x.test"}, Outbound: "block"},
	}
	raw, err := Render(d)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Apps map[string]struct {
			Route struct {
				Rules []map[string]any `json:"rules"`
			} `json:"route"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	rules := cfg.Apps[EgressApp].Route.Rules
	if len(rules) != 3 || rules[0]["rule_set"] == nil || rules[1]["auth_user"] == nil || rules[2]["ip_is_private"] != true {
		t.Errorf("rules = %+v", rules)
	}
}

func TestNeedsACertificate(t *testing.T) {
	d := daemon(spec.Options{NaiveDest: "127.0.0.1:8443"})
	d.Inbounds[0].Security.CertPath = ""
	if _, err := Render(d); err == nil {
		t.Error("rendered a server without a certificate")
	}
}
