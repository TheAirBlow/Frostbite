package spec

import "testing"

func TestSS2022KeySizes(t *testing.T) {
	_, k128 := CredentialsFor(ProtoShadowsocks, "2022-blake3-aes-128-gcm", "u", "secret")
	_, k256 := CredentialsFor(ProtoShadowsocks, "2022-blake3-aes-256-gcm", "u", "secret")
	if len(k128) != 24 || len(k256) != 44 {
		t.Fatalf("base64 key lengths should be 24 and 44, got %d and %d", len(k128), len(k256))
	}
	if _, plain := CredentialsFor(ProtoTrojan, "", "u", "secret"); plain != "secret" {
		t.Fatal("other protocols should keep the master password")
	}
}

func TestSystemUserIsStable(t *testing.T) {
	a, b := SystemUser("s", "bridge-1-2"), SystemUser("s", "bridge-1-2")
	if a != b || SystemUser("s", "bridge-1-3") == a || SystemUser("other", "bridge-1-2") == a {
		t.Fatal("system users should depend on the secret and name, and nothing else")
	}
	if len(a.UUID) != 36 {
		t.Fatalf("not a uuid: %q", a.UUID)
	}
}

func TestUserNameRoundTrip(t *testing.T) {
	if id, ok := UserID(UserName(42)); !ok || id != 42 {
		t.Fatal("user label should round trip")
	}
	if _, ok := UserID("bridge-1-2"); ok {
		t.Fatal("system users are not real users")
	}
}

func TestValidateCatchesPortClash(t *testing.T) {
	d := Daemon{Inbounds: []Inbound{
		{Tag: "a", Protocol: ProtoVLESS, Port: 443, Security: Security{Type: SecurityNone}},
		{Tag: "b", Protocol: ProtoTrojan, Port: 443, Security: Security{Type: SecurityNone}},
	}}
	if d.Validate() == nil {
		t.Fatal("two tcp inbounds on one port should be rejected")
	}
	d.Inbounds[1].Protocol = ProtoHysteria2
	d.Inbounds[1].Security = Security{Type: SecurityTLS, CertPath: "c", KeyPath: "k"}
	if err := d.Validate(); err != nil {
		t.Fatalf("tcp and udp may share a port: %v", err)
	}
}
