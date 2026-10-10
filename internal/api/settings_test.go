package api

import "testing"

func TestBrandingValidation(t *testing.T) {
	ok := []SubSettings{{}, {Accent: "#fff"}, {Accent: "#7cc8f7", LogoURL: "https://x.test/l.png"}, {LogoURL: "data:image/png;base64,AAAA"}}
	for _, s := range ok {
		if msg := s.brandingOK(); msg != "" {
			t.Errorf("%+v should be fine, got %q", s, msg)
		}
	}
	bad := []SubSettings{{Accent: "red"}, {Accent: "#12"}, {LogoURL: "javascript:alert(1)"}, {LogoURL: "ftp://x/y.png"}}
	for _, s := range bad {
		if s.brandingOK() == "" {
			t.Errorf("%+v should be rejected", s)
		}
	}
}
