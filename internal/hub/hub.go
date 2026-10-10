// Package hub keeps track of connected daemons and pushes their desired state.
package hub

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"frostbite/internal/common"
	"frostbite/internal/compose"
	"frostbite/internal/core"
	"frostbite/internal/db"
	"frostbite/internal/link"
	"frostbite/internal/metrics"
	"frostbite/internal/spec"
)

// Hub is the panel side of every daemon link.
type Hub struct {
	q   *db.Queries
	cfg common.LinkConfig

	mu      sync.RWMutex
	conns   map[int64]*conn
	metrics map[int64]sample
	certs   map[int64][]link.CertStatus
	online  map[int64]map[int64][]string // user id -> daemon id -> ips

	// OnBlock is called when a user is cut off for using too many addresses.
	OnBlock func(userID int64, ips int)

	dirty   chan struct{}
	cmdID   int64
	waiters map[int64]chan link.Result
}

// sample is a metrics report with the time it arrived.
type sample struct {
	link.Metrics
	At time.Time
}

// New creates a hub. Run must be started for rebuilds to happen.
func New(q *db.Queries, cfg common.LinkConfig) *Hub {
	return &Hub{
		q: q, cfg: cfg,
		conns:   map[int64]*conn{},
		metrics: map[int64]sample{},
		certs:   map[int64][]link.CertStatus{},
		online:  map[int64]map[int64][]string{},
		dirty:   make(chan struct{}, 1),
		waiters: map[int64]chan link.Result{},
	}
}

// MarkDirty asks for every daemon to be rebuilt soon. Bursts of changes collapse into one rebuild.
func (h *Hub) MarkDirty() {
	select {
	case h.dirty <- struct{}{}:
	default:
	}
}

// Run rebuilds daemon specs whenever something marked the hub dirty, until ctx ends.
func (h *Hub) Run(ctx context.Context) {
	h.MarkDirty()
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.dirty:
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(h.cfg.PushDebounce):
		}

		start := time.Now()
		err := h.Rebuild(ctx, 0)
		metrics.HubRebuilds.WithLabelValues(metrics.Result(err)).Inc()
		metrics.HubRebuildSecs.Observe(time.Since(start).Seconds())
		if err != nil {
			slog.Error("hub: rebuild failed", "err", err)
		}
	}
}

// Rebuild recomputes daemon specs and pushes the ones that changed. With only set, just that daemon is rebuilt and always pushed.
func (h *Hub) Rebuild(ctx context.Context, only int64) error {
	snap, err := compose.Load(ctx, h.q)
	if err != nil {
		return err
	}

	for id, d := range snap.Daemons {
		if only != 0 && id != only {
			continue
		}
		if !d.Enabled {
			continue
		}

		sp, err := snap.Build(id)
		if err == nil {
			err = checkSpec(sp)
		}
		if err != nil {
			metrics.SpecsBuilt.WithLabelValues("rejected").Inc()
			slog.Warn("hub: spec rejected", "daemon", id, "err", err)
			_ = h.q.SetDaemonApplied(ctx, db.SetDaemonAppliedParams{ID: id, AppliedRev: d.AppliedRev, LastError: err.Error()})
			continue
		}

		metrics.SpecsBuilt.WithLabelValues("accepted").Inc()
		hash := compose.Hash(sp)
		rev := d.DesiredRev
		changed := hash != d.SpecHash
		if changed {
			rev++
			metrics.SpecRevisions.Inc()
			if err := h.q.SetDaemonRevision(ctx, db.SetDaemonRevisionParams{ID: id, DesiredRev: rev, SpecHash: hash}); err != nil {
				return fmt.Errorf("daemon %d revision: %w", id, err)
			}
		}
		if changed || only != 0 {
			sp.Revision = rev
			h.push(id, link.Spec{Revision: rev, Daemon: sp})
		}
	}
	return nil
}

// checkSpec validates a spec and makes sure its core can run it.
func checkSpec(sp spec.Daemon) error {
	if err := sp.Validate(); err != nil {
		return err
	}
	desc := core.Get(sp.Kind)
	if desc == nil {
		return fmt.Errorf("unknown core %q", sp.Kind)
	}
	return desc.Caps.Check(sp)
}

// Preview renders the native config a daemon would get right now.
func (h *Hub) Preview(ctx context.Context, daemonID int64) ([]byte, error) {
	snap, err := compose.Load(ctx, h.q)
	if err != nil {
		return nil, err
	}
	sp, err := snap.Build(daemonID)
	if err != nil {
		return nil, err
	}
	if err := checkSpec(sp); err != nil {
		return nil, err
	}
	return core.Get(sp.Kind).Render(sp)
}
