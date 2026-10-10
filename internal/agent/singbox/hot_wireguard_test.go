//go:build with_wireguard && with_gvisor && !race

package singbox

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"frostbite/internal/core"
	"frostbite/internal/keys"
	"frostbite/internal/spec"
)

func TestWireGuardChangesPeersLive(t *testing.T) {
	newKey := func() string {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(k.Bytes())
	}
	hexPub := func(priv string) string {
		pub, err := keys.WireGuardPublic(priv)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := base64.StdEncoding.DecodeString(pub)
		return hex.EncodeToString(raw)
	}
	port := freePort(t)
	server := newKey()
	u1 := spec.User{ID: 1, Name: "u1", Password: newKey()}
	u2 := spec.User{ID: 2, Name: "u2", Password: newKey()}

	r := New(t.TempDir())
	t.Cleanup(func() { r.Close() })
	apply := func(users ...spec.User) {
		t.Helper()
		d := daemonWith(spec.ProtoWireGuard, port, spec.Security{Type: spec.SecurityNone}, users...)
		d.Inbounds[0].Options = spec.Options{WGSubnet: "10.8.0.0/24", WGPrivate: server}
		rendered, err := core.Get("singbox").Render(d)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Apply(context.Background(), d, rendered); err != nil {
			t.Fatal(err)
		}
	}
	peers := func() string {
		t.Helper()
		ep, ok := r.instance.Endpoint().Get("v")
		if !ok {
			t.Fatal("no endpoint")
		}
		dev, err := wireguardDevice(ep)
		if err != nil {
			t.Fatal(err)
		}
		out := dev.MethodByName("IpcGet").Call(nil)
		if e, _ := out[1].Interface().(error); e != nil {
			t.Fatal(e)
		}
		return out[0].String()
	}

	apply(u1)
	box := r.instance
	if got := peers(); !strings.Contains(got, hexPub(u1.Password)) || strings.Contains(got, hexPub(u2.Password)) {
		t.Fatalf("unexpected peers:\n%s", got)
	}
	apply(u1, u2)
	if r.instance != box {
		t.Fatal("adding a peer restarted sing-box")
	}
	got := peers()
	if !strings.Contains(got, hexPub(u1.Password)) || !strings.Contains(got, hexPub(u2.Password)) || !strings.Contains(got, "allowed_ip=10.8.0.3/32") {
		t.Fatalf("the new peer is missing:\n%s", got)
	}
	apply(u2)
	if r.instance != box {
		t.Fatal("removing a peer restarted sing-box")
	}
	if got := peers(); strings.Contains(got, hexPub(u1.Password)) || !strings.Contains(got, hexPub(u2.Password)) {
		t.Fatalf("the removed peer is still there:\n%s", got)
	}
}
