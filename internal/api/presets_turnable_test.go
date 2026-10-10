package api

import (
	"testing"

	"frostbite/internal/spec"
)

func TestTurnablePresetBuildsAValidInbound(t *testing.T) {
	var p *preset
	for i := range presets {
		if presets[i].ID == "turnable-vk" {
			p = &presets[i]
		}
	}
	if p == nil {
		t.Fatal("no turnable preset")
	}
	req := inboundRequest{Tag: "t", Listen: "0.0.0.0"}
	if err := p.build(presetValues{"call": "abc123"}, &req); err != nil {
		t.Fatal(err)
	}
	d := spec.Daemon{Kind: "turnable", Inbounds: []spec.Inbound{req.specInbound()}}
	if err := d.Validate(); err != nil {
		t.Fatalf("the preset's defaults should be valid once a call id is given: %v", err)
	}
	if req.Options.TPrivate == "" || req.Options.TPrivate == req.Options.TPublic {
		t.Fatal("the preset must generate a key pair")
	}

	empty := inboundRequest{Tag: "t", Listen: "0.0.0.0"}
	_ = p.build(presetValues{}, &empty)
	d = spec.Daemon{Kind: "turnable", Inbounds: []spec.Inbound{empty.specInbound()}}
	if err := d.Validate(); err == nil {
		t.Fatal("a missing call id must be refused")
	}
}
