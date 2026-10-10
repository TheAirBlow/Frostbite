//go:build !race

package singbox

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"frostbite/internal/core"
	"frostbite/internal/spec"
)

// connectStatus asks a plain HTTP proxy to open a tunnel and returns the status it answers with.
func connectStatus(t *testing.T, proxy, target, user, pass string) int {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxy, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\nPadding: xxxxxxxx\r\n\r\n", target, target, cred)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0
	}
	return resp.StatusCode
}

func TestNaiveChangesUsersLive(t *testing.T) {
	target := echo(t)
	port := freePort(t)
	r := New(t.TempDir())
	t.Cleanup(func() { r.Close() })
	apply := func(users ...spec.User) {
		t.Helper()
		d := daemonWith(spec.ProtoNaive, port, spec.Security{Type: spec.SecurityNone}, users...)
		d.Inbounds[0].RawPatch = []byte(`{"network":"tcp"}`)
		rendered, err := core.Get("singbox").Render(d)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Apply(context.Background(), d, rendered); err != nil {
			t.Fatal(err)
		}
	}
	u1 := spec.User{ID: 1, Name: "u1", Password: "p1"}
	u2 := spec.User{ID: 2, Name: "u2", Password: "p2"}
	proxy := fmt.Sprintf("127.0.0.1:%d", port)

	apply(u1)
	box := r.instance
	if got := connectStatus(t, proxy, target, "u1", "p1"); got != 200 {
		t.Fatalf("the first user should get in, got %d", got)
	}
	if got := connectStatus(t, proxy, target, "u2", "p2"); got == 200 {
		t.Fatal("a user nobody added must not get in")
	}
	apply(u1, u2)
	if r.instance != box {
		t.Fatal("adding a user restarted sing-box")
	}
	if got := connectStatus(t, proxy, target, "u2", "p2"); got != 200 {
		t.Fatalf("the new user should get in without a restart, got %d", got)
	}
	apply(u2)
	if r.instance != box {
		t.Fatal("removing a user restarted sing-box")
	}
	if got := connectStatus(t, proxy, target, "u1", "p1"); got == 200 {
		t.Fatal("a removed user must not get in")
	}
	apply()
	if r.instance != box {
		t.Fatal("removing the last user restarted sing-box")
	}
	if got := connectStatus(t, proxy, target, "u2", "p2"); got == 200 {
		t.Fatal("nobody may get in once the last user is gone")
	}
}
