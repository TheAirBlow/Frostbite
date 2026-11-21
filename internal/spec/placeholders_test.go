package spec

import "testing"

func TestExpandPlaceholders(t *testing.T) {
	p := Placeholders{"node": "Hostup", "country": "se", "protocol": "trojan", "remark": "Hostup trojan"}
	cases := map[string]string{
		"{flag} {node}":              "🇸🇪 Hostup",
		"{country_name}":             "Sweden",
		"{country_name:ru}":          "Швеция",
		"{country_name:zz-bad}":      "Sweden",
		"{protocol:upper}":           "TROJAN",
		"{node:lower}":               "hostup",
		"{remark} ({protocol})":      "Hostup trojan (trojan)",
		"{unknown} {protocol:shout}": "{unknown} {protocol:shout}",
		"no placeholders":            "no placeholders",
	}
	for tpl, want := range cases {
		if got := p.Expand(tpl); got != want {
			t.Errorf("%q: got %q, want %q", tpl, got, want)
		}
	}
}

func TestExpandURLEscapesValues(t *testing.T) {
	p := Placeholders{"uuid": "u-1", "host": "127.0.0.1", "port": "10800", "password": "p w&d", "name": "Frankfurt ✓"}
	got := p.ExpandURL("vless://{uuid}@{host}:{port}?x={password}#{name}")
	if want := "vless://u-1@127.0.0.1:10800?x=p+w%26d#Frankfurt+%E2%9C%93"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if p.ExpandURL("a://{unknown}") != "a://{unknown}" {
		t.Fatal("an unknown placeholder is left as it is")
	}
}

func TestCountryWithoutCode(t *testing.T) {
	p := Placeholders{"country": ""}
	if got := p.Expand("[{flag}][{country_name}]"); got != "[][]" {
		t.Fatalf("a node without a country gives empty values, got %q", got)
	}
}

func TestCheckPlaceholders(t *testing.T) {
	ok := []string{"{node} {flag}", "{country_name:ru}", "{country_name:pt-BR}", "{protocol:upper}", "plain"}
	for _, tpl := range ok {
		if err := CheckPlaceholders(tpl, RemarkPlaceholders); err != nil {
			t.Errorf("%q: %v", tpl, err)
		}
	}
	bad := []string{"{uuid}", "{remark}", "{flag:ru}", "{node:shout}", "{country_name:1}"}
	for _, tpl := range bad {
		if CheckPlaceholders(tpl, RemarkPlaceholders) == nil {
			t.Errorf("%q should be refused in a remark", tpl)
		}
	}
	if err := CheckPlaceholders("{remark} {route}", RouteNamePlaceholders); err != nil {
		t.Errorf("route names can use {remark} and {route}: %v", err)
	}
}
