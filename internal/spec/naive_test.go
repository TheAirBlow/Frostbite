package spec

import "testing"

func TestNaiveValidation(t *testing.T) {
	base := func(o Options) Daemon {
		return Daemon{Kind: "caddy", Inbounds: []Inbound{{Tag: "n", Protocol: ProtoNaive, Port: 443, Security: Security{Type: SecurityTLS}, Options: o}}}
	}
	cases := []struct {
		name string
		o    Options
		ok   bool
	}{
		{"minimal", Options{NaiveDest: "127.0.0.1:8443"}, true},
		{"everything", Options{NaiveDest: "site.internal:443", NaiveProxy: "v2", NaiveHeader: "X-Real-IP"}, true},
		{"no header", Options{NaiveDest: "127.0.0.1:80", NaiveHeader: NaiveNoHeader}, true},
		{"no site", Options{}, false},
		{"no port", Options{NaiveDest: "127.0.0.1"}, false},
		{"bad port", Options{NaiveDest: "127.0.0.1:99999"}, false},
		{"bad proxy", Options{NaiveDest: "127.0.0.1:80", NaiveProxy: "v3"}, false},
		{"bad header", Options{NaiveDest: "127.0.0.1:80", NaiveHeader: "X Real IP"}, false},
	}
	for _, c := range cases {
		d := base(c.o)
		if err := d.Validate(); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}

	// sing-box serves naive without a site, so only the Caddy daemon asks for one
	d := base(Options{})
	d.Kind = "singbox"
	if err := d.Validate(); err != nil {
		t.Errorf("sing-box: %v", err)
	}
}

func TestNaiveIPHeader(t *testing.T) {
	for in, want := range map[string]string{"": NaiveDefaultHeader, NaiveNoHeader: "", "X-Real-IP": "X-Real-IP"} {
		if got := (Options{NaiveHeader: in}).NaiveIPHeader(); got != want {
			t.Errorf("%q resolves to %q, want %q", in, got, want)
		}
	}
}
