package spec

import "testing"

func TestWGAddress(t *testing.T) {
	cases := []struct {
		subnet string
		id     int64
		want   string
	}{
		{"10.8.0.0/16", 1, "10.8.0.2"},
		{"10.8.0.0/16", 300, "10.8.1.45"},
		{"10.8.5.77/24", 3, "10.8.5.4"},
	}
	for _, c := range cases {
		got, err := WGAddress(c.subnet, c.id)
		if err != nil || got != c.want {
			t.Errorf("WGAddress(%s,%d) = %q, %v; want %q", c.subnet, c.id, got, err, c.want)
		}
	}
	if _, err := WGAddress("10.8.0.0/24", 254); err == nil {
		t.Error("a user past the end of the subnet should be refused")
	}
	if _, err := WGAddress("fd00::/64", 1); err == nil {
		t.Error("only ipv4 subnets are handled")
	}
}

func TestWGServerAddress(t *testing.T) {
	if got, _ := WGServerAddress("10.8.0.0/16"); got != "10.8.0.1/16" {
		t.Fatalf("got %q", got)
	}
}

func TestWGKeysAreValidAndStable(t *testing.T) {
	_, a := CredentialsFor(ProtoWireGuard, "", "u", "secret")
	_, b := CredentialsFor(ProtoWireGuard, "", "u", "secret")
	_, c := CredentialsFor(ProtoWireGuard, "", "u", "other")
	if a != b || a == c || len(a) != 44 {
		t.Fatalf("keys should be stable per secret and base64 of 32 bytes: %q %q %q", a, b, c)
	}
}
