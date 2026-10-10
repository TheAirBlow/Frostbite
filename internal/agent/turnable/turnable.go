// Package turnable runs Turnable servers: tunnels that hide inside a call on a platform such as VK. Each inbound is one
// server, and users change on a running server without dropping anyone else.
package turnable

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"reflect"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"

	tconfig "github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/config/providers"
	"github.com/theairblow/turnable/pkg/connection/relay"
	"github.com/theairblow/turnable/pkg/engine"
	_ "github.com/theairblow/turnable/pkg/init"

	"frostbite/internal/agent/logs"
	"frostbite/internal/link"
	"frostbite/internal/spec"
)

// instance is a running Turnable server, as far as the runtime cares.
type instance interface {
	Stop() error
	CollectUsage() map[string]engine.Usage
	Users() []engine.UserStats
	KickUser(uuid string) int
}

// starter brings up a server for an inbound that reads its users and route from prov.
type starter func(in spec.Inbound, prov *providers.RawProvider, log *slog.Logger) (instance, error)

// Runtime is the Turnable daemon.
type Runtime struct {
	logs  *logs.Ring
	start starter

	mu      sync.Mutex
	servers map[string]*server
	last    spec.Daemon
}

// shape is everything about an inbound that needs a restart when it changes.
type shape struct {
	Listen  string
	Port    int
	Options spec.Options
}

// member is a user as the server knows them.
type member struct {
	label  string
	peers  int
	routes string // the ids of the routes the user may take, comma separated
}

// server is one running inbound.
type server struct {
	shape shape
	inst  instance
	prov  *providers.RawProvider

	mu     sync.Mutex
	users  map[string]member // who may connect, by uuid
	labels map[string]string // every uuid seen on this server, so the last traffic of a removed user is still booked
}

// New creates a runtime.
func New() *Runtime {
	// the server has nobody to solve a captcha for
	tconfig.Options.Interactive = false
	return &Runtime{logs: logs.NewRing(1000), start: startServer, servers: map[string]*server{}}
}

// Kind is the core this runtime drives.
func (r *Runtime) Kind() string { return "turnable" }

// CoreVersion identifies the Turnable build.
func (r *Runtime) CoreVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/theairblow/turnable" {
				return "turnable " + dep.Version
			}
		}
	}
	return "turnable"
}

func (r *Runtime) logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	slog.Info("turnable: " + msg)
	fmt.Fprintf(r.logs, "%s\n", msg)
}

// Apply starts, updates and stops servers to match d. Users change without dropping anyone else.
func (r *Runtime) Apply(_ context.Context, d spec.Daemon, _ []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last = d

	want := map[string]bool{}
	var failed []error
	for _, in := range d.Inbounds {
		if in.Protocol != spec.ProtoTurnable {
			continue
		}
		want[in.Tag] = true
		sh := shape{Listen: in.Listen, Port: in.Port, Options: in.Options.TurnableDefaults()}

		if s, ok := r.servers[in.Tag]; ok {
			if reflect.DeepEqual(s.shape, sh) {
				s.sync(in)
				continue
			}
			r.stop(in.Tag, s)
		}
		s, err := r.launch(in, sh, d.Log.Level)
		if err != nil {
			failed = append(failed, fmt.Errorf("%s: %w", in.Tag, err))
			continue
		}
		r.servers[in.Tag] = s
		r.logf("%s: serving on %s:%d", in.Tag, in.Listen, in.Port)
	}
	for tag, s := range r.servers {
		if !want[tag] {
			r.stop(tag, s)
		}
	}
	return errors.Join(failed...)
}

// launch starts a server for an inbound.
func (r *Runtime) launch(in spec.Inbound, sh shape, level string) (*server, error) {
	var routes []providers.Route
	for _, r := range sh.Options.TRoutes {
		host, port, err := r.Split()
		if err != nil {
			return nil, fmt.Errorf("route %s: %w", r.ID, err)
		}
		name := r.Name
		if name == "" {
			name = in.Tag
		}
		routes = append(routes, providers.Route{ID: r.ID, Address: host, Port: port, Socket: r.Socket, Transport: r.Transport, Encryption: r.Encryption, Name: name})
	}
	if len(routes) == 0 {
		return nil, errors.New("no destination to lead the tunnel to")
	}
	s := &server{shape: sh, users: map[string]member{}, labels: map[string]string{}}
	raw, err := json.Marshal(map[string]any{"routes": routes, "users": []providers.User{}})
	if err != nil {
		return nil, err
	}
	s.prov = &providers.RawProvider{}
	if err := s.prov.Update(raw); err != nil {
		return nil, err
	}
	s.sync(in)

	lvl := slog.LevelInfo
	if level == "debug" {
		lvl = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(io.MultiWriter(r.logs, os.Stderr), &slog.HandlerOptions{Level: lvl}))
	inst, err := r.start(in, s.prov, log)
	if err != nil {
		return nil, err
	}
	s.inst = inst
	return s, nil
}

// stop shuts a server down and forgets it.
func (r *Runtime) stop(tag string, s *server) {
	if err := s.inst.Stop(); err != nil {
		r.logf("%s: stopping: %v", tag, err)
	}
	delete(r.servers, tag)
	r.logf("%s: stopped", tag)
}

// sync makes the server's users match the inbound's, cutting off the ones that are gone.
func (s *server) sync(in spec.Inbound) {
	o := in.Options.TurnableDefaults()
	peers := o.TPeers
	allowed := make([]string, len(o.TRoutes))
	for i, r := range o.TRoutes {
		allowed[i] = r.ID
	}
	want := map[string]member{}
	for _, u := range in.Users {
		if u.UUID != "" {
			want[u.UUID] = member{label: u.Name, peers: peers, routes: strings.Join(allowed, ",")}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for id, m := range want {
		s.labels[id] = m.label
		if old, ok := s.users[id]; ok && old == m {
			continue
		}
		_ = s.prov.AddUser(&providers.User{UUID: id, AllowedRoutes: strings.Split(m.routes, ","), Type: "relay", Peers: m.peers})
	}
	for id := range s.users {
		if _, ok := want[id]; !ok {
			_ = s.prov.DeleteUser(id)
			if s.inst != nil {
				s.inst.KickUser(id)
			}
		}
	}
	s.users = want
}

// Stats returns usage since the last call and who is connected now.
func (r *Runtime) Stats(context.Context) (link.Stats, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	st := link.Stats{Users: map[string]link.Usage{}, Online: map[string][]string{}}
	for _, s := range r.servers {
		s.mu.Lock()
		for id, u := range s.inst.CollectUsage() {
			if label, ok := s.labels[id]; ok {
				cur := st.Users[label]
				cur.Up += u.Up
				cur.Down += u.Down
				st.Users[label] = cur
			}
		}
		for _, u := range s.inst.Users() {
			label, ok := s.labels[u.UUID]
			if !ok || !u.Online {
				continue
			}
			for _, ip := range u.IPs {
				if !contains(st.Online[label], ip) {
					st.Online[label] = append(st.Online[label], ip)
				}
			}
		}
		s.mu.Unlock()
	}
	return st, nil
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// Restart drops every tunnel and starts the servers again.
func (r *Runtime) Restart(ctx context.Context) error {
	r.mu.Lock()
	for tag, s := range r.servers {
		r.stop(tag, s)
	}
	last := r.last
	r.mu.Unlock()
	return r.Apply(ctx, last, nil)
}

// Logs returns the tail of the log.
func (r *Runtime) Logs(lines int) string { return r.logs.Tail(lines) }

// Close stops everything.
func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for tag, s := range r.servers {
		r.stop(tag, s)
	}
	return nil
}

// startServer runs a real Turnable relay server.
func startServer(in spec.Inbound, prov *providers.RawProvider, log *slog.Logger) (instance, error) {
	o := in.Options.TurnableDefaults()
	listen := in.Listen
	if listen == "" {
		listen = "0.0.0.0"
	}
	cfg := &relay.ServerConfig{
		ServerConfig: tconfig.ServerConfig{Type: "relay", Provider: in.Tag, PlatformID: o.TPlatform, CallID: o.TCallID},
		Proto:        o.TProto, PubKey: o.TPublic, PrivKey: o.TPrivate, Cloak: "none",
		PublicIP:   "127.0.0.1", // only used to write client configs, which the panel does itself
		ListenAddr: net.JoinHostPort(listen, strconv.Itoa(in.Port)),
	}
	srv := engine.NewTurnableServer(cfg, prov)
	srv.SetLogger(log)
	if err := srv.Start(); err != nil {
		return nil, err
	}
	return srv, nil
}
