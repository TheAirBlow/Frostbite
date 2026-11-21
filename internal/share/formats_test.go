package share

import (
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"

	"frostbite/internal/spec"
)

func tunedProfiles() []spec.Upstream {
	return []spec.Upstream{{
		Name: "ws", Protocol: spec.ProtoTrojan, Address: "a.example", Port: 443, Password: "pw",
		Transport: spec.Transport{Type: spec.TransportWS, Path: "/ws", Host: "cdn.example", EarlyData: 2048, Headers: map[string]string{"X-A": "b"}},
		Security:  spec.Security{Type: spec.SecurityTLS, SNI: "cdn.example"},
		Options: spec.Options{
			Mux:      &spec.Mux{Enabled: true, Protocol: "smux", Concurrency: 4, Padding: true},
			Fragment: &spec.Frag{Enabled: true, Length: "50-100"},
		},
	}, {
		Name: "hy", Protocol: spec.ProtoHysteria2, Address: "h.example", Port: 443, Password: "pw",
		Security: spec.Security{SNI: "h.example"},
		Options:  spec.Options{UpMbps: 50, DownMbps: 200, Mux: &spec.Mux{Enabled: true}, Fragment: &spec.Frag{Enabled: true}},
	}, {
		Name: "tuic", Protocol: spec.ProtoTUIC, Address: "t.example", Port: 443, UUID: "u", Password: "pw",
		Options: spec.Options{ZeroRTT: true, Heartbeat: "10s"},
	}}
}

// at walks nested maps and slices by key or index.
func at(v any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, _ := v.(map[string]any)
			v = m[k]
		case int:
			s, _ := v.([]any)
			if k >= len(s) {
				return nil
			}
			v = s[k]
		}
	}
	return v
}

func byKey(list any, key, value string) any {
	for _, x := range list.([]any) {
		if at(x, key) == value {
			return x
		}
	}
	return nil
}

func TestSingboxCarriesClientOptions(t *testing.T) {
	body, err := Render(FormatSingbox, tunedProfiles(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var cfg any
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatal(err)
	}
	ws := byKey(at(cfg, "outbounds"), "tag", "ws")
	if at(ws, "multiplex", "protocol") != "smux" || at(ws, "multiplex", "max_streams") != 4.0 || at(ws, "multiplex", "padding") != true {
		t.Errorf("multiplex: %v", at(ws, "multiplex"))
	}
	if at(ws, "tls", "fragment") != true {
		t.Errorf("tls: %v", at(ws, "tls"))
	}
	hy := byKey(at(cfg, "outbounds"), "tag", "hy")
	if at(hy, "multiplex") != nil || at(hy, "tls", "fragment") != nil {
		t.Errorf("hysteria2 has neither mux nor hello fragmentation: %v", hy)
	}
	if tu := byKey(at(cfg, "outbounds"), "tag", "tuic"); at(tu, "heartbeat") != "10s" || at(tu, "zero_rtt_handshake") != true {
		t.Errorf("tuic: %v", tu)
	}
}

func TestXrayCarriesClientOptions(t *testing.T) {
	body, err := Render(FormatXray, tunedProfiles()[:1], nil)
	if err != nil {
		t.Fatal(err)
	}
	var docs []any
	if err := json.Unmarshal(body, &docs); err != nil {
		t.Fatal(err)
	}
	outs := at(docs[0], "outbounds")
	proxy := byKey(outs, "tag", "proxy")
	if at(proxy, "mux", "concurrency") != 4.0 {
		t.Errorf("mux: %v", at(proxy, "mux"))
	}
	if at(proxy, "streamSettings", "sockopt", "dialerProxy") != "fragment" {
		t.Errorf("sockopt: %v", at(proxy, "streamSettings"))
	}
	frag := at(byKey(outs, "tag", "fragment"), "settings", "fragment")
	if at(frag, "packets") != "tlshello" || at(frag, "length") != "50-100" || at(frag, "interval") != "10-20" {
		t.Errorf("fragment: %v", frag)
	}
}

func TestClashCarriesClientOptions(t *testing.T) {
	body, err := Render(FormatClash, tunedProfiles(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(body, &cfg); err != nil {
		t.Fatal(err)
	}
	ws := byKey(cfg["proxies"], "name", "ws")
	if at(ws, "smux", "protocol") != "smux" || at(ws, "smux", "max-streams") != 4 || at(ws, "smux", "padding") != true {
		t.Errorf("smux: %v", at(ws, "smux"))
	}
	if at(ws, "ws-opts", "max-early-data") != 2048 || at(ws, "ws-opts", "headers", "X-A") != "b" || at(ws, "ws-opts", "headers", "Host") != "cdn.example" {
		t.Errorf("ws-opts: %v", at(ws, "ws-opts"))
	}
	hy := byKey(cfg["proxies"], "name", "hy")
	if at(hy, "up") != "50 Mbps" || at(hy, "down") != "200 Mbps" || at(hy, "smux") != nil {
		t.Errorf("hysteria2: %v", hy)
	}
	if tu := byKey(cfg["proxies"], "name", "tuic"); at(tu, "reduce-rtt") != true || at(tu, "heartbeat-interval") != 10000 {
		t.Errorf("tuic: %v", tu)
	}
}
