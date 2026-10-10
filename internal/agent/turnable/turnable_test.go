package turnable

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"

	"github.com/theairblow/turnable/pkg/config/providers"
	"github.com/theairblow/turnable/pkg/engine"

	"frostbite/internal/keys"
	"frostbite/internal/spec"
)

// fake is a server that only remembers what it was asked to do.
type fake struct {
	mu      sync.Mutex
	prov    *providers.RawProvider
	stopped bool
	kicked  []string
	usage   map[string]engine.Usage
	online  []engine.UserStats
}

func (f *fake) Stop() error { f.stopped = true; return nil }
func (f *fake) CollectUsage() map[string]engine.Usage {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.usage
	f.usage = nil
	return u
}
func (f *fake) Users() []engine.UserStats { return f.online }
func (f *fake) KickUser(id string) int    { f.kicked = append(f.kicked, id); return 1 }

// harness starts a runtime on fakes and records every one it creates.
func harness(t *testing.T) (*Runtime, *[]*fake) {
	t.Helper()
	var started []*fake
	r := New()
	r.start = func(_ spec.Inbound, prov *providers.RawProvider, _ *slog.Logger) (instance, error) {
		f := &fake{prov: prov}
		started = append(started, f)
		return f, nil
	}
	t.Cleanup(func() { r.Close() })
	return r, &started
}

var (
	pairOnce sync.Once
	pair     keys.TurnablePair
)

func inbound(t *testing.T, users ...spec.User) spec.Daemon {
	t.Helper()
	pairOnce.Do(func() {
		var err error
		if pair, err = keys.Turnable(); err != nil {
			t.Fatal(err)
		}
	})
	in := spec.Inbound{
		Tag: "t", Protocol: spec.ProtoTurnable, Listen: "0.0.0.0", Port: 56000, Users: users,
		Options: spec.Options{TCallID: "abc", TTarget: "127.0.0.1:51820", TSocket: "udp", TPrivate: pair.Private, TPublic: pair.Public},
	}
	d := spec.Daemon{Kind: "turnable", Inbounds: []spec.Inbound{in}}
	if err := d.Validate(); err != nil {
		t.Fatalf("the inbound under test is not valid: %v", err)
	}
	return d
}

func user(n int) spec.User {
	id, _ := spec.CredentialsFor(spec.ProtoTurnable, "", fmt.Sprintf("00000000-0000-4000-8000-%012d", n), fmt.Sprintf("secret%d", n))
	return spec.User{ID: int64(n), Name: fmt.Sprintf("u%d", n), UUID: id}
}

func TestUsersChangeOnARunningServer(t *testing.T) {
	r, started := harness(t)
	u1, u2 := user(1), user(2)
	ctx := context.Background()

	if err := r.Apply(ctx, inbound(t, u1), nil); err != nil {
		t.Fatal(err)
	}
	if len(*started) != 1 {
		t.Fatalf("expected one server, got %d", len(*started))
	}
	f := (*started)[0]
	if _, err := f.prov.GetUser(u1.UUID); err != nil {
		t.Fatalf("the first user should be known: %v", err)
	}
	if rt, err := f.prov.GetRoute(spec.TurnableRoute); err != nil || rt.Port != 51820 || rt.Socket != "udp" {
		t.Fatalf("route is wrong: %+v %v", rt, err)
	}

	// someone arrives
	if err := r.Apply(ctx, inbound(t, u1, u2), nil); err != nil {
		t.Fatal(err)
	}
	if len(*started) != 1 || f.stopped {
		t.Fatal("adding a user restarted the server")
	}
	if _, err := f.prov.GetUser(u2.UUID); err != nil {
		t.Fatalf("the new user should be known: %v", err)
	}

	// someone leaves
	if err := r.Apply(ctx, inbound(t, u2), nil); err != nil {
		t.Fatal(err)
	}
	if len(*started) != 1 || f.stopped {
		t.Fatal("removing a user restarted the server")
	}
	if _, err := f.prov.GetUser(u1.UUID); err == nil {
		t.Fatal("a removed user must not be accepted")
	}
	if len(f.kicked) != 1 || f.kicked[0] != u1.UUID {
		t.Fatalf("the removed user's tunnels should be cut, kicked %v", f.kicked)
	}
}

func TestOtherChangesRestartTheServer(t *testing.T) {
	r, started := harness(t)
	d := inbound(t, user(1))
	if err := r.Apply(context.Background(), d, nil); err != nil {
		t.Fatal(err)
	}
	d.Inbounds[0].Options.TPeers = 3
	if err := r.Apply(context.Background(), d, nil); err != nil {
		t.Fatal(err)
	}
	if len(*started) != 2 || !(*started)[0].stopped {
		t.Fatalf("a changed option should replace the server, started %d", len(*started))
	}
}

func TestRemovedInboundStopsItsServer(t *testing.T) {
	r, started := harness(t)
	if err := r.Apply(context.Background(), inbound(t, user(1)), nil); err != nil {
		t.Fatal(err)
	}
	if err := r.Apply(context.Background(), spec.Daemon{Kind: "turnable"}, nil); err != nil {
		t.Fatal(err)
	}
	if !(*started)[0].stopped {
		t.Fatal("the server should stop when its inbound goes")
	}
}

func TestStatsAreBookedByLabel(t *testing.T) {
	r, started := harness(t)
	u1, u2 := user(1), user(2)
	if err := r.Apply(context.Background(), inbound(t, u1, u2), nil); err != nil {
		t.Fatal(err)
	}
	f := (*started)[0]
	f.usage = map[string]engine.Usage{u1.UUID: {Up: 10, Down: 20}, "stranger": {Up: 1}}
	f.online = []engine.UserStats{{UUID: u1.UUID, Online: true, IPs: []string{"1.2.3.4"}}, {UUID: u2.UUID, Online: false}}

	st, err := r.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Users["u1"]; got.Up != 10 || got.Down != 20 {
		t.Fatalf("usage should land on the label: %+v", st.Users)
	}
	if _, ok := st.Users["stranger"]; ok {
		t.Fatal("traffic of an unknown id must not be booked")
	}
	if len(st.Online["u1"]) != 1 || len(st.Online["u2"]) != 0 {
		t.Fatalf("online is wrong: %v", st.Online)
	}

	// the traffic a user left behind is still counted after they are removed
	f.usage = map[string]engine.Usage{u1.UUID: {Up: 5}}
	if err := r.Apply(context.Background(), inbound(t, u2), nil); err != nil {
		t.Fatal(err)
	}
	st, _ = r.Stats(context.Background())
	if st.Users["u1"].Up != 5 {
		t.Fatalf("the last traffic of a removed user was lost: %+v", st.Users)
	}
}
