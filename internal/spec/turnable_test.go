package spec

import (
	"crypto/mlkem"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
)

func turnableOptions(t *testing.T) Options {
	t.Helper()
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	return Options{
		TCallID: "abc", TTarget: "127.0.0.1:51820", TSocket: "udp",
		TPrivate: base64.StdEncoding.EncodeToString(dk.Bytes()),
		TPublic:  base64.StdEncoding.EncodeToString(dk.EncapsulationKey().Bytes()),
	}
}

func TestTurnableInboundValidation(t *testing.T) {
	cases := map[string]func(o *Options){
		"valid":                   func(o *Options) {},
		"no call id":              func(o *Options) { o.TCallID = "" },
		"unknown platform":        func(o *Options) { o.TPlatform = "example.com" },
		"unknown wrapper":         func(o *Options) { o.TProto = "tls" },
		"unknown transport":       func(o *Options) { o.TTransport = "quic" },
		"tcp without a transport": func(o *Options) { o.TSocket, o.TTransport = "tcp", "none" },
		"no socket":               func(o *Options) { o.TSocket = "" },
		"destination is a name":   func(o *Options) { o.TTarget = "localhost:443" },
		"destination no port":     func(o *Options) { o.TTarget = "127.0.0.1" },
		"bad public key":          func(o *Options) { o.TPublic = "AAAA" },
		"bad private key":         func(o *Options) { o.TPrivate = "AAAA" },
		"unknown encryption":      func(o *Options) { o.TEncryption = "none" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := turnableOptions(t)
			mutate(&o)
			err := o.validateTurnable()
			if (name == "valid") != (err == nil) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestTurnableCredentialIsItsOwn(t *testing.T) {
	id, pass := CredentialsFor(ProtoTurnable, "", "11111111-1111-4111-8111-111111111111", "master")
	again, _ := CredentialsFor(ProtoTurnable, "", "11111111-1111-4111-8111-111111111111", "master")
	other, _ := CredentialsFor(ProtoTurnable, "", "11111111-1111-4111-8111-111111111111", "rotated")
	if _, err := uuid.Parse(id); err != nil {
		t.Fatalf("turnable needs a uuid: %v", err)
	}
	if id != again || id == other {
		t.Fatal("the credential must follow the master secret and nothing else")
	}
	if id == "11111111-1111-4111-8111-111111111111" {
		t.Fatal("the account uuid must not double as the turnable secret")
	}
	if pass != "master" {
		t.Fatal("the password is not used")
	}
}

func TestTurnableListensOnUDP(t *testing.T) {
	if (Inbound{Protocol: ProtoTurnable}).Network() != "udp" {
		t.Fatal("turnable wrappers run over UDP")
	}
}

func fieldOf(err error) string {
	path, _, _ := FieldOf(err)
	return path
}

func TestTurnableRoutesNameTheFieldThatIsWrong(t *testing.T) {
	good := TurnableRouteSpec{ID: "web", Target: "10.0.0.5:443", Socket: "tcp"}
	cases := map[string]struct {
		routes []TurnableRouteSpec
		field  string
	}{
		"two good routes":   {[]TurnableRouteSpec{good, {ID: "wg", Target: "127.0.0.1:51820", Socket: "udp"}}, ""},
		"no routes":         {nil, "options.t_routes"},
		"bad id":            {[]TurnableRouteSpec{{ID: "Web Server", Target: "10.0.0.5:443", Socket: "tcp"}}, "options.t_routes.0.id"},
		"duplicate id":      {[]TurnableRouteSpec{good, good}, "options.t_routes.1.id"},
		"second target bad": {[]TurnableRouteSpec{good, {ID: "wg", Target: "nope", Socket: "udp"}}, "options.t_routes.1.target"},
		"no socket":         {[]TurnableRouteSpec{{ID: "wg", Target: "10.0.0.5:1"}}, "options.t_routes.0.socket"},
		"tcp over none":     {[]TurnableRouteSpec{{ID: "wg", Target: "10.0.0.5:1", Socket: "tcp", Transport: "none"}}, "options.t_routes.0.transport"},
		"bad encryption":    {[]TurnableRouteSpec{{ID: "wg", Target: "10.0.0.5:1", Socket: "udp", Encryption: "rot13"}}, "options.t_routes.0.encryption"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			o := turnableOptions(t)
			o.TTarget, o.TSocket = "", ""
			o.TRoutes = c.routes
			err := o.validateTurnable()
			if c.field == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || fieldOf(err) != c.field {
				t.Fatalf("want an error on %s, got %v", c.field, err)
			}
		})
	}
}

func TestTurnableCallIDErrorPointsAtItsField(t *testing.T) {
	o := turnableOptions(t)
	o.TCallID = ""
	if got := fieldOf(o.validateTurnable()); got != "options.t_call_id" {
		t.Fatalf("got %q", got)
	}
}

func TestOlderFlatDestinationBecomesTheMainRoute(t *testing.T) {
	o := turnableOptions(t) // uses TTarget and TSocket
	routes := o.TurnableRoutes()
	if len(routes) != 1 || routes[0].ID != TurnableRoute || routes[0].Target != "127.0.0.1:51820" || routes[0].Transport != TurnableTransport {
		t.Fatalf("got %+v", routes)
	}
	m := o.MigrateTurnable()
	if m.TTarget != "" || m.TSocket != "" || len(m.TRoutes) != 1 || m.TRoutes[0].ID != TurnableRoute {
		t.Fatalf("migration left %+v", m)
	}
	if err := m.validateTurnable(); err != nil {
		t.Fatal(err)
	}
}
