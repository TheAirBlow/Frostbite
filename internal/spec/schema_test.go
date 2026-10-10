package spec

import "testing"

func TestParseUIKeepsCommasInValues(t *testing.T) {
	got := parseUI("label=DNS servers,hint=Plain IPs, https:// or tls:// URLs,advanced")
	if got["hint"] != "Plain IPs, https:// or tls:// URLs" {
		t.Fatalf("hint was split: %q", got["hint"])
	}
	if _, ok := got["advanced"]; !ok {
		t.Fatal("advanced flag lost")
	}
}

func TestSchemaHasNestedReality(t *testing.T) {
	found := false
	for _, f := range Schema()["security"] {
		if f.Path == "reality.dest" {
			found = true
		}
	}
	if !found {
		t.Fatal("reality.dest missing from security schema")
	}
}
