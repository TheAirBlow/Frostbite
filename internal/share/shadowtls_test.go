package share

import (
	"strings"
	"testing"

	"frostbite/internal/spec"
)

func stlsProfile() spec.Upstream {
	return spec.Upstream{
		Name: "n1", Protocol: spec.ProtoShadowTLS, Address: "1.2.3.4", Port: 443, Password: "outer",
		Options: spec.Options{Handshake: "www.example.com:443"},
		Inner:   &spec.Upstream{Protocol: spec.ProtoShadowsocks, Address: "127.0.0.1", Port: 9, Password: "inner", Options: spec.Options{Method: "chacha20-ietf-poly1305"}},
	}
}

func TestShadowTLSSingbox(t *testing.T) {
	out, err := Render(FormatSingbox, []spec.Upstream{stlsProfile()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{`"type": "shadowtls"`, `"detour": "n1 (shadowtls)"`, `"server_name": "www.example.com"`, `"method": "chacha20-ietf-poly1305"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
}

func TestShadowTLSClash(t *testing.T) {
	out, err := Render(FormatClash, []spec.Upstream{stlsProfile()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"plugin: shadow-tls", "host: www.example.com", "server: 1.2.3.4"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
}
