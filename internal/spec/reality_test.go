package spec

import "testing"

func TestRealityXverIsBounded(t *testing.T) {
	for _, tc := range []struct {
		ver int
		ok  bool
	}{{0, true}, {1, true}, {2, true}, {3, false}, {-1, false}} {
		in := Inbound{Protocol: ProtoVLESS, Security: Security{Type: SecurityReality, Reality: &Reality{
			Dest: "127.0.0.1:8443", ServerNames: []string{"a.example"}, PrivateKey: "k", XVer: tc.ver,
		}}}
		if err := in.validateSecurity(); (err == nil) != tc.ok {
			t.Fatalf("xver %d: got %v", tc.ver, err)
		}
	}
}
