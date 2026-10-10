package share

import (
	"strings"
	"testing"

	"frostbite/internal/spec"
)

func TestMTProtoLink(t *testing.T) {
	up := spec.Upstream{Name: "n", Protocol: spec.ProtoMTProto, Address: "1.2.3.4", Port: 443, Password: "00112233445566778899aabbccddeeff", Options: spec.Options{MTMode: "faketls", MTDomain: "a.io"}}
	got, err := Link(up)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "secret=ee00112233445566778899aabbccddeeff612e696f") || !strings.HasPrefix(got, "tg://proxy?") {
		t.Fatalf("link %s", got)
	}
	up.Options.MTMode = "padded"
	got, _ = Link(up)
	if !strings.Contains(got, "secret=dd0011") {
		t.Fatalf("link %s", got)
	}
}

func TestMTProtoSkippedByClientFormats(t *testing.T) {
	mt := spec.Upstream{Name: "tg", Protocol: spec.ProtoMTProto, Address: "1.2.3.4", Port: 443, Password: "00112233445566778899aabbccddeeff", Options: spec.Options{MTMode: "padded"}}
	ss := spec.Upstream{Name: "ss", Protocol: spec.ProtoShadowsocks, Address: "1.2.3.4", Port: 8388, Password: "pw", Options: spec.Options{Method: "aes-128-gcm"}}
	for _, f := range []string{FormatSingbox, FormatClash, FormatXray, FormatLinks, FormatRaw} {
		out, err := Render(f, []spec.Upstream{mt, ss}, nil)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if f != FormatLinks && f != FormatRaw && strings.Contains(string(out), "tg://") {
			t.Errorf("%s carries the telegram link", f)
		}
	}
}
