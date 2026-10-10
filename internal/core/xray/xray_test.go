package xray

import (
	"encoding/json"
	"testing"

	"frostbite/internal/spec"
)

func sample() spec.Daemon {
	return spec.Daemon{
		Kind: "xray",
		Inbounds: []spec.Inbound{{
			Tag: "reality-in", Protocol: spec.ProtoVLESS, Port: 443,
			Transport: spec.Transport{Type: spec.TransportTCP},
			Security: spec.Security{Type: spec.SecurityReality, Reality: &spec.Reality{
				Dest: "www.cloudflare.com:443", ServerNames: []string{"www.cloudflare.com"}, PrivateKey: "priv", ShortIDs: []string{"ab"},
			}},
			Options: spec.Options{Flow: "xtls-rprx-vision"},
			Users:   []spec.User{{ID: 1, Name: "u1", UUID: "5783a3e7-e373-51cd-8642-c83782b807c5"}},
		}},
		Outbounds: []spec.Outbound{{Tag: "direct", Kind: spec.OutDirect}, {Tag: "block", Kind: spec.OutBlock}},
		Rules:     []spec.Rule{{Protocol: []string{"bittorrent"}, Outbound: "block"}},
		Final:     "direct",
	}
}

func TestRenderReality(t *testing.T) {
	raw, err := Render(sample())
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("output is not json: %v", err)
	}
	if _, ok := cfg["stats"]; !ok {
		t.Fatal("stats block missing")
	}
	ins := cfg["inbounds"].([]any)
	if len(ins) != 2 {
		t.Fatalf("want api + 1 inbound, got %d", len(ins))
	}
	in := ins[1].(map[string]any)
	client := in["settings"].(map[string]any)["clients"].([]any)[0].(map[string]any)
	if client["flow"] != "xtls-rprx-vision" || client["email"] != "u1" {
		t.Fatalf("client rendered wrong: %v", client)
	}
	rs := in["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
	ids := rs["shortIds"].([]any)
	if len(ids) != 2 || ids[0] != "" {
		t.Fatalf("short ids should keep the empty id first: %v", ids)
	}
}

func TestVisionDroppedOnWS(t *testing.T) {
	d := sample()
	d.Inbounds[0].Transport = spec.Transport{Type: spec.TransportWS, Path: "/x"}
	d.Inbounds[0].Security = spec.Security{Type: spec.SecurityNone}
	raw, err := Render(d)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = json.Unmarshal(raw, &cfg)
	client := cfg["inbounds"].([]any)[1].(map[string]any)["settings"].(map[string]any)["clients"].([]any)[0].(map[string]any)
	if _, ok := client["flow"]; ok {
		t.Fatal("flow must not be set on ws")
	}
}

func TestRawPatch(t *testing.T) {
	d := sample()
	d.Inbounds[0].RawPatch = json.RawMessage(`{"sniffing":{"enabled":true},"tag":"renamed"}`)
	raw, err := Render(d)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = json.Unmarshal(raw, &cfg)
	in := cfg["inbounds"].([]any)[1].(map[string]any)
	if in["tag"] != "renamed" || in["sniffing"] == nil {
		t.Fatalf("patch not applied: %v", in)
	}
}

func TestRealityXverReachesTheConfig(t *testing.T) {
	for _, ver := range []int{0, 1, 2} {
		d := sample()
		d.Inbounds[0].Security.Reality.XVer = ver
		raw, err := Render(d)
		if err != nil {
			t.Fatal(err)
		}
		var cfg map[string]any
		_ = json.Unmarshal(raw, &cfg)
		rs := cfg["inbounds"].([]any)[1].(map[string]any)["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
		if rs["xver"] != float64(ver) {
			t.Fatalf("xver %d rendered as %v", ver, rs["xver"])
		}
	}
}
