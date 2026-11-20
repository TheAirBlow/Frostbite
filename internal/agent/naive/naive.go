// Package naive runs the naive daemon: Caddy with the NaiveProxy fork of forwardproxy, in this process. The gate keeps
// the users, counts their traffic and can cut them off, so changing users never reloads the config and never drops
// anyone who stays.
package naive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	caddycore "github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/caddyserver/forwardproxy"

	"frostbite/internal/agent/logs"
	"frostbite/internal/agent/naive/gate"
	"frostbite/internal/link"
	"frostbite/internal/spec"
)

// Runtime runs Caddy.
type Runtime struct {
	logs *logs.Ring

	mu    sync.Mutex
	cfg   []byte                       // the config Caddy runs, nil until one has loaded
	want  []byte                       // the config the panel asked for, kept so a failed load can be retried
	users map[string][]gate.Credential // the users the gate knows, by inbound
}

// New creates a runtime.
func New() *Runtime {
	r := &Runtime{logs: logs.NewRing(2000), users: map[string][]gate.Credential{}}
	gate.SetLogSink(io.MultiWriter(r.logs, os.Stderr))
	return r
}

// Kind is the core this runtime drives.
func (r *Runtime) Kind() string { return "naive" }

// CoreVersion identifies the Caddy build.
func (r *Runtime) CoreVersion() string {
	v, _ := caddycore.Version()
	fields := strings.Fields(v)
	if len(fields) == 0 {
		return "naive"
	}
	return "caddy " + strings.TrimPrefix(fields[0], "v")
}

// usersOf lists who may use each inbound.
func usersOf(d spec.Daemon) map[string][]gate.Credential {
	out := map[string][]gate.Credential{}
	for _, in := range d.Inbounds {
		if in.Protocol != spec.ProtoNaive {
			continue
		}
		list := []gate.Credential{}
		for _, u := range in.Users {
			list = append(list, gate.Credential{Name: u.Name, Password: u.Password})
		}
		slices.SortFunc(list, func(a, b gate.Credential) int { return strings.Compare(a.Name, b.Name) })
		out[in.Tag] = list
	}
	return out
}

// Apply brings Caddy in line with d. Users change in the gate, and the config is only loaded when it differs.
func (r *Runtime) Apply(_ context.Context, d spec.Daemon, rendered []byte) error {
	users := usersOf(d)

	r.mu.Lock()
	defer r.mu.Unlock()

	// users go first, so one added together with a new inbound can connect the moment it opens
	for tag, list := range users {
		if !reflect.DeepEqual(r.users[tag], list) {
			r.setUsers(tag, list)
		}
	}
	for tag := range r.users {
		if _, ok := users[tag]; !ok {
			// an inbound that is gone must not keep its tunnels
			r.setUsers(tag, nil)
		}
	}
	r.users = users

	r.want = rendered
	if bytes.Equal(rendered, r.cfg) {
		return nil
	}
	if err := r.load(rendered); err != nil {
		return err
	}
	r.cfg = rendered
	return nil
}

// setUsers replaces the users of one inbound.
func (r *Runtime) setUsers(tag string, list []gate.Credential) {
	if cut := gate.Replace(tag, list); cut > 0 {
		slog.Info("caddy: cut tunnels of users that are gone", "inbound", tag, "tunnels", cut)
	}
}

// load has Caddy switch to a config. Connections it already serves stay open, and a config it rejects changes nothing.
func (r *Runtime) load(cfg []byte) error {
	if err := caddycore.Load(cfg, true); err != nil {
		return fmt.Errorf("caddy rejected the config: %w", err)
	}
	return nil
}

// Reload has Caddy read its config and certificate files again without dropping anyone.
func (r *Runtime) Reload(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.want == nil {
		return errors.New("there is no config to run yet")
	}
	if err := r.load(r.want); err != nil {
		return err
	}
	r.cfg = r.want
	return nil
}

// Restart stops Caddy and starts it again, which drops every tunnel.
func (r *Runtime) Restart(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.want == nil {
		return errors.New("there is no config to run yet")
	}
	r.stop()
	r.cfg = nil
	if err := r.load(r.want); err != nil {
		return err
	}
	r.cfg = r.want
	return nil
}

// stop shuts Caddy down. It waits for open connections, so the tunnels are cut first.
func (r *Runtime) stop() {
	gate.CutAll()
	done := make(chan struct{})
	go func() {
		_ = caddycore.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		slog.Warn("caddy did not stop in time")
	}
}

// Close stops Caddy for good.
func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cfg != nil {
		r.stop()
		r.cfg = nil
	}
	r.want = nil
	return nil
}

// Logs returns the tail of Caddy's output.
func (r *Runtime) Logs(lines int) string { return r.logs.Tail(lines) }

// Stats returns the traffic since the last call and who is connected now.
func (r *Runtime) Stats(context.Context) (link.Stats, error) {
	rep := gate.Drain()
	st := link.Stats{Users: map[string]link.Usage{}, Online: rep.Online}
	for name, u := range rep.Users {
		st.Users[name] = link.Usage{Up: u.Up, Down: u.Down}
	}
	return st, nil
}
