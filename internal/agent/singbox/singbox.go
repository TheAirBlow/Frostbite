// Package singbox runs sing-box inside the agent, so per user accounting needs no extra api.
package singbox

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"

	"frostbite/internal/link"
	"frostbite/internal/spec"
)

// maxLog is how big the log file may get before it is started over.
const maxLog = 8 << 20

// Runtime runs sing-box.
type Runtime struct {
	dataDir string

	mu       sync.Mutex
	instance *box.Box
	cancel   context.CancelFunc
	rendered []byte
	tracker  *tracker
	cur      *spec.Daemon
	slots    map[string]*slotState
}

// New creates a runtime. dataDir holds the log and the last config.
func New(dataDir string) *Runtime {
	return &Runtime{dataDir: dataDir, tracker: newTracker()}
}

// Kind is the core this runtime drives.
func (r *Runtime) Kind() string { return "singbox" }

// CoreVersion is the embedded sing-box version.
func (r *Runtime) CoreVersion() string { return "sing-box " + C.Version }

// logPath is where sing-box writes its log.
func (r *Runtime) logPath() string { return filepath.Join(r.dataDir, "sing-box.log") }

// Apply makes d the running config. A change that only touches users is applied live (see hot.go); anything else starts a fresh instance.
func (r *Runtime) Apply(ctx context.Context, d spec.Daemon, rendered []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.tracker.setPeers(peersOf(d))

	cp := d
	if r.instance != nil && string(r.rendered) == string(rendered) {
		r.cur = &cp
		return nil
	}

	if r.instance != nil && r.cur != nil && spec.SameShape(*r.cur, d) {
		err := r.hot(*r.cur, d)
		if err == nil {
			r.cur, r.rendered = &cp, append([]byte(nil), rendered...)
			slog.Info("users updated without a restart")
			return nil
		}
		slog.Info("restarting sing-box to change users", "why", err)
	}

	next, slots, cancel, err := r.build(rendered, d)
	if err != nil {
		return err
	}

	prevRendered := r.rendered
	prevSpec := spec.Daemon{}
	if r.cur != nil {
		prevSpec = *r.cur
	}
	r.stopLocked()
	if err := next.Start(); err != nil {
		cancel()
		_ = next.Close()
		if prevRendered != nil {
			slog.Warn("new config failed to start, putting the previous one back", "err", err)
			if old, oldSlots, oldCancel, berr := r.build(prevRendered, prevSpec); berr == nil {
				if old.Start() == nil {
					r.instance, r.cancel, r.rendered, r.slots = old, oldCancel, prevRendered, oldSlots
				} else {
					oldCancel()
				}
			}
		}
		return fmt.Errorf("sing-box failed to start: %w", err)
	}

	r.instance, r.cancel, r.rendered, r.slots, r.cur = next, cancel, append([]byte(nil), rendered...), slots, &cp
	slog.Info("sing-box started")
	return nil
}

// build parses a config into a ready, not yet started instance.
func (r *Runtime) build(rendered []byte, d spec.Daemon) (*box.Box, map[string]*slotState, context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(include.Context(context.Background()))

	var opts option.Options
	if err := opts.UnmarshalJSONContext(ctx, rendered); err != nil {
		cancel()
		return nil, nil, nil, fmt.Errorf("sing-box rejected the config: %w", err)
	}
	slots := layoutOf(&opts, d)
	if opts.Log == nil {
		opts.Log = &option.LogOptions{}
	}
	opts.Log.Output = r.logPath()
	opts.Log.DisableColor = true
	if info, err := os.Stat(r.logPath()); err == nil && info.Size() > maxLog {
		_ = os.Truncate(r.logPath(), 0)
	}

	instance, err := box.New(box.Options{Options: opts, Context: ctx})
	if err != nil {
		cancel()
		return nil, nil, nil, fmt.Errorf("sing-box rejected the config: %w", err)
	}
	instance.Router().AppendTracker(r.tracker)
	return instance, slots, cancel, nil
}

// stopLocked stops the running instance. The caller holds the lock.
func (r *Runtime) stopLocked() {
	if r.instance == nil {
		return
	}
	_ = r.instance.Close()
	r.cancel()
	r.instance, r.cancel = nil, nil
	r.tracker.dropAll()
}

// Restart starts the core over with the current config.
func (r *Runtime) Restart(ctx context.Context) error {
	r.mu.Lock()
	rendered := append([]byte(nil), r.rendered...)
	r.rendered = nil
	r.mu.Unlock()
	if len(rendered) == 0 {
		return fmt.Errorf("there is no config to run yet")
	}
	r.mu.Lock()
	var d spec.Daemon
	if r.cur != nil {
		d = *r.cur
	}
	r.mu.Unlock()
	return r.Apply(ctx, d, rendered)
}

// Close stops sing-box for good.
func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopLocked()
	return nil
}

// Logs returns the tail of sing-box's log.
func (r *Runtime) Logs(lines int) string {
	raw, err := os.ReadFile(r.logPath())
	if err != nil {
		return ""
	}
	all := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return strings.Join(all, "\n")
}

// Stats drains per user counters and lists who is connected.
func (r *Runtime) Stats(ctx context.Context) (link.Stats, error) {
	r.mu.Lock()
	running := r.instance != nil
	r.mu.Unlock()
	if !running {
		return link.Stats{}, fmt.Errorf("sing-box is not running")
	}
	return r.tracker.drain(), nil
}

// peersOf maps each WireGuard user's tunnel address to their label, since tunnels carry no user name of their own.
func peersOf(d spec.Daemon) map[string]string {
	out := map[string]string{}
	for _, in := range d.Inbounds {
		if in.Protocol != spec.ProtoWireGuard {
			continue
		}
		for _, u := range in.Users {
			if ip, err := spec.WGAddress(in.Options.WGSubnet, u.ID); err == nil {
				out[ip] = u.Name
			}
		}
	}
	return out
}
