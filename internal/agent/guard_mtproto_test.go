package agent

import (
	"context"
	"net"
	"testing"
	"time"

	"frostbite/internal/agent/mtproto"
	"frostbite/internal/spec"
)

func TestGuardHaltsInProcessCoreAndHandsPortBack(t *testing.T) {
	target, _ := tlsSite(t, false)
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()

	d := spec.Daemon{Kind: "mtproto", Inbounds: []spec.Inbound{{
		Tag: "mt", Protocol: spec.ProtoMTProto, Listen: "127.0.0.1", Port: port, Transport: spec.Transport{Type: "tcp"},
		Options: spec.Options{MTMode: "faketls", MTDomain: "site.example.com", Guard: &spec.Guard{Enabled: true, Target: target}},
	}}}
	rt := mtproto.New()
	g := newGuards(rt)
	if err := rt.Apply(context.Background(), d, nil); err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	g.Want(d)

	rt.Halt()
	g.round(context.Background())
	addr := (&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}).String()
	if err := probeTLS(context.Background(), addr, "site.example.com", 5*time.Second, 0); err != nil {
		t.Fatalf("port not served after the core was halted: %v", err)
	}

	if err := rt.Restart(context.Background()); err != nil {
		t.Fatalf("the core could not get its port back: %v", err)
	}
	if !rt.Alive() {
		t.Fatal("core not running after a restart")
	}
	g.mu.Lock()
	for _, gd := range g.list {
		if gd.ln != nil {
			t.Fatal("the guard kept the port")
		}
	}
	g.mu.Unlock()
}
