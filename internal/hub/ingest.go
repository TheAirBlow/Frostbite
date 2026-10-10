package hub

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"frostbite/internal/db"
	"frostbite/internal/link"
	"frostbite/internal/metrics"
	"frostbite/internal/spec"
)

// blockFor is how long a user who broke their ip limit stays cut off.
const blockFor = 5 * time.Minute

// ingest books a usage report against users, the node and the hourly series.
func (h *Hub) ingest(ctx context.Context, d db.Daemon, s link.Stats) {
	defer func(start time.Time) { metrics.IngestSeconds.Observe(time.Since(start).Seconds()) }(time.Now())
	node, err := h.nodeOf(ctx, d)
	if err != nil {
		slog.Error("hub: node lookup failed", "daemon", d.ID, "err", err)
		return
	}

	var raw, billedUp, billedDown int64
	changed := false
	for label, u := range s.Users {
		raw += u.Up + u.Down
		id, ok := spec.UserID(label)
		if !ok || u.Up+u.Down == 0 {
			continue
		}

		up := int64(float64(u.Up) * node.TrafficMultiplier)
		down := int64(float64(u.Down) * node.TrafficMultiplier)
		user, err := h.q.AddUserUsage(ctx, db.AddUserUsageParams{ID: id, TrafficUsed: up + down})
		if err != nil {
			metrics.IngestUnknown.Inc()
			slog.Debug("hub: usage for unknown user", "label", label, "err", err)
			continue
		}
		billedUp += up
		billedDown += down
		if err := h.q.AddTraffic(ctx, db.AddTrafficParams{UserID: id, NodeID: node.ID, Up: up, Down: down}); err != nil {
			slog.Error("hub: saving traffic failed", "user", id, "err", err)
		}
		if user.TrafficLimit > 0 && user.TrafficUsed >= user.TrafficLimit {
			changed = true
			metrics.LimitHits.Inc()
		}
	}
	nodeID, nodeName := itoa(node.ID), node.Name
	if billedUp > 0 {
		metrics.TrafficBilled.WithLabelValues(nodeID, nodeName, "up").Add(float64(billedUp))
	}
	if billedDown > 0 {
		metrics.TrafficBilled.WithLabelValues(nodeID, nodeName, "down").Add(float64(billedDown))
	}
	if raw > 0 {
		metrics.TrafficRaw.WithLabelValues(nodeID, nodeName).Add(float64(raw))
	}
	if len(s.Online) > 0 {
		metrics.OnlineSnapshots.Inc()
	}
	if raw > 0 {
		if err := h.q.AddNodeTraffic(ctx, db.AddNodeTrafficParams{ID: node.ID, TrafficUsed: raw}); err != nil {
			slog.Error("hub: saving node traffic failed", "node", node.ID, "err", err)
		}
	}

	if h.trackOnline(ctx, d.ID, s.Online) {
		changed = true
	}
	if changed {
		h.MarkDirty()
	}
}

// nodeOf finds the node a daemon belongs to.
func (h *Hub) nodeOf(ctx context.Context, d db.Daemon) (db.Node, error) {
	return h.q.GetNode(ctx, d.NodeID)
}

// trackOnline stores who is connected and cuts off users who exceed their ip limit.
func (h *Hub) trackOnline(ctx context.Context, daemonID int64, online map[string][]string) bool {
	h.mu.Lock()
	for uid, byDaemon := range h.online {
		delete(byDaemon, daemonID)
		if len(byDaemon) == 0 {
			delete(h.online, uid)
		}
	}
	over := map[int64]int{}
	for label, ips := range online {
		id, ok := spec.UserID(label)
		if !ok {
			continue
		}
		if h.online[id] == nil {
			h.online[id] = map[int64][]string{}
		}
		h.online[id][daemonID] = ips
		over[id] = len(h.unionIPs(id))
	}
	h.mu.Unlock()

	blocked := false
	for id, n := range over {
		u, err := h.q.GetUser(ctx, id)
		if err != nil || u.IpLimit == 0 || n <= int(u.IpLimit) {
			continue
		}
		until := time.Now().Add(blockFor)
		if err := h.q.BlockUser(ctx, db.BlockUserParams{ID: id, BlockedUntil: &until}); err == nil {
			slog.Info("hub: user over ip limit, blocked", "user", u.Username, "ips", n, "limit", u.IpLimit)
			blocked = true
			metrics.IPLimitBlocks.Inc()
			if h.OnBlock != nil {
				h.OnBlock(id, n)
			}
		}
	}
	return blocked
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
