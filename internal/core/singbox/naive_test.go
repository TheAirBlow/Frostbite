package singbox

import (
	"testing"

	"frostbite/internal/spec"
)

func TestNaiveOutbound(t *testing.T) {
	m, err := OutboundFor(spec.Upstream{Protocol: spec.ProtoNaive, Address: "a.example", Port: 443, Username: "bob", Password: "pw", Security: spec.Security{SNI: "a.example"}}, "n")
	if err != nil {
		t.Fatal(err)
	}
	if m["type"] != "naive" || m["username"] != "bob" || m["tls"] == nil {
		t.Fatalf("unexpected outbound %v", m)
	}
}
