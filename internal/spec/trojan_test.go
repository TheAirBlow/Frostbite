package spec

import "testing"

func TestTrojanValidation(t *testing.T) {
	daemon := func(kind string, o Options) Daemon {
		return Daemon{Kind: kind, Inbounds: []Inbound{{Tag: "t", Protocol: ProtoTrojan, Port: 443, Security: Security{Type: SecurityTLS}, Options: o}}}
	}
	site := "127.0.0.1:80"
	for _, c := range []struct {
		name string
		o    Options
		ok   bool
	}{
		{"minimal", Options{TJDest: site}, true},
		{"everything", Options{
			TJDest: "site.internal:443", TJTLS: true, TJProxy: "v1", TJIPHeader: "X-Real-IP", TJHeaders: map[string]string{"X-A": "b"},
			TJBySNI: map[string]string{"*.a.example": site}, TJByALPN: map[string]string{"h2": site}, TJByPath: map[string]string{"/ws": site},
			TJPlain: TrojanPlainNginx, TJMinTLS: "1.3", TJCiphers: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			TJCurves: []string{"X25519MLKEM768", "x25519", "prime256v1"}, TJUDPIdle: 120,
		}, true},
		{"no site", Options{}, false},
		{"bad site port", Options{TJDest: "127.0.0.1:0"}, false},
		{"bad proxy", Options{TJDest: site, TJProxy: "v3"}, false},
		{"bad header", Options{TJDest: site, TJIPHeader: "X Real IP"}, false},
		{"bad extra header", Options{TJDest: site, TJHeaders: map[string]string{"a b": "c"}}, false},
		{"bad name", Options{TJDest: site, TJBySNI: map[string]string{"a/b": site}}, false},
		{"bad name site", Options{TJDest: site, TJBySNI: map[string]string{"a.example": "nope"}}, false},
		{"bad path", Options{TJDest: site, TJByPath: map[string]string{"ws": site}}, false},
		{"bad plain", Options{TJDest: site, TJPlain: "teapot"}, false},
		{"bad tls", Options{TJDest: site, TJMinTLS: "1.1"}, false},
		{"tls 1.3 suite", Options{TJDest: site, TJCiphers: []string{"TLS_AES_128_GCM_SHA256"}}, false},
		{"bad curve", Options{TJDest: site, TJCurves: []string{"P-192"}}, false},
		{"bad udp timeout", Options{TJDest: site, TJUDPIdle: 4000}, false},
	} {
		d := daemon("trojan", c.o)
		err := d.Validate()
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}

	// xray and sing-box serve trojan without a site of their own
	if d := daemon("xray", Options{}); d.Validate() != nil {
		err := d.Validate()
		t.Errorf("xray trojan: %v", err)
	}
	plain := daemon("trojan", Options{TJDest: site})
	plain.Inbounds[0].Security = Security{Type: SecurityNone}
	if err := plain.Validate(); err == nil {
		t.Error("the trojan daemon took an inbound without tls")
	}
}
