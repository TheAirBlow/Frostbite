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
