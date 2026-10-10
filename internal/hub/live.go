package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"frostbite/internal/link"
	"frostbite/internal/metrics"
)

// Live is the in-memory state of one daemon.
type Live struct {
	Online    bool              `json:"online"`
	Since     *time.Time        `json:"since,omitempty"`
	Metrics   *link.Metrics     `json:"metrics,omitempty"`
	MetricsAt *time.Time        `json:"metrics_at,omitempty"`
	Certs     []link.CertStatus `json:"certs,omitempty"`
}

// Status reports the live state of a daemon.
func (h *Hub) Status(daemonID int64) Live {
	h.mu.RLock()
	defer h.mu.RUnlock()
	c := h.conns[daemonID]
	if c == nil {
		return Live{}
	}
	l := Live{Online: true, Since: &c.since, Certs: h.certs[daemonID]}
	if s, ok := h.metrics[daemonID]; ok {
		m := s.Metrics
		at := s.At
		l.Metrics, l.MetricsAt = &m, &at
	}
	return l
}

// OnlineIPs returns the addresses a user is currently connected from, across all daemons.
func (h *Hub) OnlineIPs(userID int64) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.unionIPs(userID)
}

// OnlineUserIDs lists every user with at least one live connection.
func (h *Hub) OnlineUserIDs() []int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	ids := make([]int64, 0, len(h.online))
	for id := range h.online {
		ids = append(ids, id)
	}
	return ids
}

// unionIPs merges a user's addresses over every daemon. The caller holds the lock.
func (h *Hub) unionIPs(userID int64) []string {
	seen := map[string]bool{}
	var out []string
	for _, ips := range h.online[userID] {
		for _, ip := range ips {
			if !seen[ip] {
				seen[ip] = true
				out = append(out, ip)
			}
		}
	}
	return out
}

// dropOnline forgets what a disconnected daemon reported. The caller holds the lock.
func (h *Hub) dropOnline(daemonID int64) {
	for uid, byDaemon := range h.online {
		delete(byDaemon, daemonID)
		if len(byDaemon) == 0 {
			delete(h.online, uid)
		}
	}
}

// ErrOffline means the daemon is not connected.
var ErrOffline = errors.New("daemon is offline")

// Command runs a command on a daemon and waits for its answer.
func (h *Hub) Command(ctx context.Context, daemonID int64, name string, args map[string]string) (res link.Result, err error) {
	start := time.Now()
	defer func() {
		outcome := "ok"
		switch {
		case errors.Is(err, ErrOffline):
			outcome = "offline"
		case err != nil:
			outcome = "error"
		case !res.OK:
			outcome = "failed"
		}
		metrics.CommandsSent.WithLabelValues(name, outcome).Inc()
		if err == nil {
			metrics.CommandSeconds.WithLabelValues(name).Observe(time.Since(start).Seconds())
		}
	}()
	h.mu.Lock()
	c := h.conns[daemonID]
	if c == nil {
		h.mu.Unlock()
		return link.Result{}, ErrOffline
	}
	h.cmdID++
	id := h.cmdID
	ch := make(chan link.Result, 1)
	h.waiters[id] = ch
	h.mu.Unlock()

	c.send(link.TypeCmd, link.Cmd{ID: id, Name: name, Args: args})

	select {
	case r := <-ch:
		return r, nil
	case <-time.After(20 * time.Second):
		h.mu.Lock()
		delete(h.waiters, id)
		h.mu.Unlock()
		return link.Result{}, fmt.Errorf("daemon did not answer in time")
	case <-ctx.Done():
		return link.Result{}, ctx.Err()
	}
}

// decodeBody unpacks an envelope body.
func decodeBody(m link.Message, v any) error { return json.Unmarshal(m.Body, v) }

// encodeJSON marshals v for a jsonb column.
func encodeJSON(v any) (json.RawMessage, error) { return json.Marshal(v) }

// LiveState snapshots what the hub holds in memory, for the metrics collector.
func (h *Hub) LiveState() metrics.Live {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := metrics.Live{Daemons: map[int64]metrics.DaemonLive{}, OnlineUsers: map[int64]int{}}

	users := map[int64]map[int64]bool{}
	ips := map[int64]map[string]bool{}
	for uid, byDaemon := range h.online {
		out.OnlineUsers[uid] = len(h.unionIPs(uid))
		for did, list := range byDaemon {
			if users[did] == nil {
				users[did], ips[did] = map[int64]bool{}, map[string]bool{}
			}
			users[did][uid] = true
			for _, ip := range list {
				ips[did][ip] = true
			}
		}
	}
	for id, c := range h.conns {
		d := metrics.DaemonLive{Since: c.since, Certs: h.certs[id], Users: len(users[id]), IPs: len(ips[id])}
		if s, ok := h.metrics[id]; ok {
			m := s.Metrics
			d.Metrics, d.MetricsAt = &m, s.At
		}
		out.Daemons[id] = d
	}
	return out
}
