// Package trojan runs the trojan daemon: a native trojan server that sends everyone who is not a trojan user on to a
// real site, the way upstream trojan does. Users live in the process, so adding and removing them never touches a
// listener, and a user who is removed is cut off at once.
package trojan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"frostbite/internal/agent/logs"
	coretrojan "frostbite/internal/core/trojan"
	"frostbite/internal/link"
	"frostbite/internal/spec"
)

// Runtime is the trojan daemon.
type Runtime struct {
	logs  *logs.Ring
	level atomic.Int32

	mu      sync.Mutex
	servers map[string]*server
	cfg     []byte // the config that runs, nil until one has applied
	want    []byte // the config the panel asked for, kept for reloads
	users   map[string]map[string]string

	router atomic.Pointer[router]

	usageMu sync.Mutex
	usage   map[string]*counter

	liveMu sync.Mutex
	live   map[*session]struct{}
}

// counter is traffic of one user since the last drain.
type counter struct{ up, down atomic.Int64 }

// session is one authenticated connection.
type session struct {
	inbound, user, hash, ip string
	kick                    func()
}

// New creates a runtime.
func New() *Runtime {
	r := &Runtime{logs: logs.NewRing(2000), servers: map[string]*server{}, users: map[string]map[string]string{},
		usage: map[string]*counter{}, live: map[*session]struct{}{}}
	r.level.Store(levelInfo)
	return r
}

// Kind is the core this runtime drives.
func (r *Runtime) Kind() string { return "trojan" }

// CoreVersion identifies the server.
func (r *Runtime) CoreVersion() string { return "frostbite-trojan 1" }

// Log levels, in order.
const (
	levelDebug int32 = iota
	levelInfo
	levelWarning
	levelError
	levelNone
)

func parseLevel(s string) int32 {
	switch s {
	case "debug":
		return levelDebug
	case "warning":
		return levelWarning
	case "error":
		return levelError
	case "none":
		return levelNone
	}
	return levelInfo
}

var levelNames = [...]string{"debug", "info", "warning", "error"}

// logf records a line at a level, if the config asks for that much.
func (r *Runtime) logf(level int32, format string, args ...any) {
	if level < r.level.Load() {
		return
	}
	msg := fmt.Sprintf(format, args...)
	switch level {
	case levelDebug:
		slog.Debug("trojan: " + msg)
	case levelWarning:
		slog.Warn("trojan: " + msg)
	case levelError:
		slog.Error("trojan: " + msg)
	default:
		slog.Info("trojan: " + msg)
	}
	fmt.Fprintf(r.logs, "%s %s %s\n", time.Now().Format("2006/01/02 15:04:05"), levelNames[level], msg)
}

// usersOf maps the password hash of every user to their name, by inbound.
func usersOf(d spec.Daemon) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, in := range d.Inbounds {
		if in.Protocol != spec.ProtoTrojan {
			continue
		}
		m := map[string]string{}
		for _, u := range in.Users {
			if u.Password != "" {
				m[passwordHash(u.Password)] = u.Name
			}
		}
		out[in.Tag] = m
	}
	return out
}

// passwordHash is how a trojan client presents its password.
func passwordHash(password string) string {
	sum := sha256.Sum224([]byte(password))
	return hex.EncodeToString(sum[:])
}

// Apply brings the listeners in line with d. Users change in place, a listener only reopens when its socket changes,
// and a new certificate or site applies to the next connection without dropping anyone.
func (r *Runtime) Apply(_ context.Context, d spec.Daemon, rendered []byte) error {
	var cfg coretrojan.Config
	if err := json.Unmarshal(rendered, &cfg); err != nil {
		return fmt.Errorf("bad config: %w", err)
	}
	rt, err := newRouter(cfg)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.level.Store(parseLevel(cfg.LogLevel))
	r.router.Store(rt)

	// users go first, so one added together with a new inbound can connect the moment it opens
	users := usersOf(d)
	for tag, list := range users {
		if !reflect.DeepEqual(r.users[tag], list) {
			if s := r.servers[tag]; s != nil {
				s.users.Store(&list)
			}
			r.kick(tag, list)
		}
	}
	r.users = users

	r.want = rendered
	err = r.apply(cfg, false)
	if err == nil {
		r.cfg = rendered
	}
	return err
}

// apply opens, updates and closes listeners. A listener that fails keeps the rest going. reread loads certificate files
// even for inbounds that did not change.
func (r *Runtime) apply(cfg coretrojan.Config, reread bool) error {
	var failed []error
	want := map[string]bool{}
	for _, ib := range cfg.Inbounds {
		want[ib.Tag] = true
		// a TLS config that stays keeps its session ticket keys, so returning visitors resume
		if s, ok := r.servers[ib.Tag]; ok && !reread && reflect.DeepEqual(s.state.Load().ib, ib) {
			continue
		}
		st, err := newState(ib)
		if err != nil {
			failed = append(failed, fmt.Errorf("inbound %s: %w", ib.Tag, err))
			continue
		}
		if s, ok := r.servers[ib.Tag]; ok && s.socket == socketOf(ib) {
			s.state.Store(st)
			continue
		} else if ok {
			r.stopServer(s)
		}
		users := r.users[ib.Tag]
		s, err := r.listen(ib, st, users)
		if err != nil {
			failed = append(failed, fmt.Errorf("inbound %s: %w", ib.Tag, err))
			continue
		}
		r.servers[ib.Tag] = s
		r.logf(levelInfo, "listening on %s (%s)", ib.Listen, ib.Tag)
	}
	for tag, s := range r.servers {
		if !want[tag] {
			r.stopServer(s)
			r.logf(levelInfo, "stopped %s (%s)", s.addr, tag)
		}
	}
	return errors.Join(failed...)
}

// stopServer closes a listener and every connection it accepted.
func (r *Runtime) stopServer(s *server) {
	_ = s.ln.Close()
	delete(r.servers, s.tag)
	s.dropAll()
	r.kick(s.tag, nil)
}

// kick cuts the sessions of an inbound whose user is no longer in users, or whose password changed.
func (r *Runtime) kick(tag string, users map[string]string) {
	r.liveMu.Lock()
	var drop []*session
	for s := range r.live {
		if s.inbound == tag && users[s.hash] != s.user {
			drop = append(drop, s)
		}
	}
	r.liveMu.Unlock()
	for _, s := range drop {
		s.kick()
	}
	if len(drop) > 0 {
		r.logf(levelInfo, "cut %d connections of users that are gone from %s", len(drop), tag)
	}
}

// open registers a session and returns the counter of its user and a function that ends it.
func (r *Runtime) open(s *session) (*counter, func()) {
	r.usageMu.Lock()
	c := r.usage[s.user]
	if c == nil {
		c = &counter{}
		r.usage[s.user] = c
	}
	r.usageMu.Unlock()
	r.liveMu.Lock()
	r.live[s] = struct{}{}
	r.liveMu.Unlock()
	return c, func() {
		r.liveMu.Lock()
		delete(r.live, s)
		r.liveMu.Unlock()
	}
}

// Stats returns the traffic since the last call and who is connected now.
func (r *Runtime) Stats(context.Context) (link.Stats, error) {
	st := link.Stats{Users: map[string]link.Usage{}, Online: map[string][]string{}}
	live := map[string]bool{}
	r.liveMu.Lock()
	for s := range r.live {
		live[s.user] = true
		if ips := st.Online[s.user]; !slices.Contains(ips, s.ip) {
			st.Online[s.user] = append(ips, s.ip)
		}
	}
	r.liveMu.Unlock()
	for _, ips := range st.Online {
		slices.Sort(ips)
	}

	r.mu.Lock()
	known := map[string]bool{}
	for _, users := range r.users {
		for _, name := range users {
			known[name] = true
		}
	}
	r.mu.Unlock()

	r.usageMu.Lock()
	defer r.usageMu.Unlock()
	for name, c := range r.usage {
		if up, down := c.up.Swap(0), c.down.Swap(0); up != 0 || down != 0 {
			st.Users[name] = link.Usage{Up: up, Down: down}
		}
		// a user that is gone and idle needs no counter any more
		if !known[name] && !live[name] {
			delete(r.usage, name)
		}
	}
	return st, nil
}

// Reload reads certificate files again. Open connections stay.
func (r *Runtime) Reload(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.want == nil {
		return errors.New("there is no config to run yet")
	}
	var cfg coretrojan.Config
	if err := json.Unmarshal(r.want, &cfg); err != nil {
		return err
	}
	if err := r.apply(cfg, true); err != nil {
		return err
	}
	r.cfg = r.want
	return nil
}

// Restart closes every listener and connection and starts again.
func (r *Runtime) Restart(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.want == nil {
		return errors.New("there is no config to run yet")
	}
	for _, s := range r.servers {
		r.stopServer(s)
	}
	r.cfg = nil
	var cfg coretrojan.Config
	if err := json.Unmarshal(r.want, &cfg); err != nil {
		return err
	}
	if err := r.apply(cfg, true); err != nil {
		return err
	}
	r.cfg = r.want
	return nil
}

// Close stops everything for good.
func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.servers {
		r.stopServer(s)
	}
	r.cfg, r.want = nil, nil
	return nil
}

// Logs returns the tail of the log.
func (r *Runtime) Logs(lines int) string { return r.logs.Tail(lines) }

// addrIP is the address part of a connection's remote end.
func addrIP(a net.Addr) string {
	if host, _, err := net.SplitHostPort(a.String()); err == nil {
		return host
	}
	return a.String()
}
