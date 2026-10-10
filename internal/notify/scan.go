package notify

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"time"

	"frostbite/internal/db"
	"frostbite/internal/metrics"
)

// offlineGrace is how long a daemon may stay away before anyone is told.
const offlineGrace = 90 * time.Second

// Scan looks for things that happen with the passage of time rather than at a moment: nearing expiry,
// nearing a traffic limit, and daemons that went quiet.
func (s *Service) Scan(ctx context.Context) {
	set := s.Settings(ctx)
	s.scanUsers(ctx, set)
	s.scanNodes(ctx)
	err := s.q.PruneNotifications(ctx, time.Now().AddDate(0, 0, -90))
	metrics.NotifyScans.WithLabelValues(metrics.Result(err)).Inc()
	if err != nil {
		slog.Warn("notify: pruning the log failed", "err", err)
	}
}

// once records a notification and reports whether it is new.
func (s *Service) once(ctx context.Context, kind, key string) bool {
	n, err := s.q.TryNotify(ctx, db.TryNotifyParams{Kind: kind, Key: key})
	return err == nil && n == 1
}

// scanUsers raises expiry and usage alerts, each at most once per threshold.
func (s *Service) scanUsers(ctx context.Context, set Settings) {
	users, err := s.q.ListNotifyCandidates(ctx)
	if err != nil {
		slog.Warn("notify: listing users failed", "err", err)
		return
	}
	days := slices.Clone(set.ExpireDays)
	slices.Sort(days)
	pcts := slices.Clone(set.UsagePercent)
	slices.Sort(pcts)

	for _, u := range users {
		if u.ExpireAt != nil && len(days) > 0 {
			left := int(math.Ceil(time.Until(*u.ExpireAt).Hours() / 24))
			// the tightest threshold the user is inside of
			for _, d := range days {
				if left >= 0 && left <= d {
					if s.once(ctx, UserExpiring, fmt.Sprintf("%d:%d:%d", u.ID, u.ExpireAt.Unix(), d)) {
						s.Emit(Event{Kind: UserExpiring, User: UserOf(u), Data: map[string]any{"days_left": left}})
					}
					break
				}
			}
		}
		if u.TrafficLimit > 0 && len(pcts) > 0 {
			pct := int(u.TrafficUsed * 100 / u.TrafficLimit)
			hit := 0
			for _, p := range pcts {
				if pct >= p {
					hit = p
				}
			}
			if hit > 0 && s.once(ctx, UserUsage, fmt.Sprintf("%d:%d:%d", u.ID, u.LastReset.Unix(), hit)) {
				s.Emit(Event{Kind: UserUsage, User: UserOf(u), Data: map[string]any{"percent": pct}})
			}
		}
	}
}

// StateChanged raises the alerts for users the quota loop just limited or expired.
func (s *Service) StateChanged(ctx context.Context, kind string, ids []int64) {
	for _, id := range ids {
		u, err := s.q.GetUser(ctx, id)
		if err != nil {
			continue
		}
		var key string
		switch kind {
		case UserLimited:
			key = fmt.Sprintf("%d:%d", u.ID, u.LastReset.Unix())
		case UserExpired:
			if u.ExpireAt == nil {
				continue
			}
			key = fmt.Sprintf("%d:%d", u.ID, u.ExpireAt.Unix())
		default:
			continue
		}
		if s.once(ctx, kind, key) {
			s.Emit(Event{Kind: kind, User: UserOf(u)})
		}
	}
}

// scanNodes announces daemons that stay away or come back.
func (s *Service) scanNodes(ctx context.Context) {
	daemons, err := s.q.ListDaemons(ctx)
	if err != nil {
		return
	}
	nodes := map[int64]string{}
	if list, err := s.q.ListNodes(ctx); err == nil {
		for _, n := range list {
			nodes[n.ID] = n.Name
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	live := map[int64]bool{}
	for _, d := range daemons {
		live[d.ID] = true
		if !d.Enabled {
			delete(s.seen, d.ID)
			continue
		}
		info := &NodeInfo{ID: d.NodeID, Name: nodes[d.NodeID], Daemon: d.Name}
		st := s.seen[d.ID]

		if s.online(d.ID) {
			if st != nil && st.announced {
				s.Emit(Event{Kind: NodeOnline, Node: info})
			}
			s.seen[d.ID] = &nodeState{}
			continue
		}
		// a daemon that was never seen up is not "offline", it just has not enrolled yet
		if st == nil {
			if d.LastSeen == nil {
				continue
			}
			s.seen[d.ID] = &nodeState{down: time.Now()}
			continue
		}
		if st.down.IsZero() {
			st.down = time.Now()
		}
		if !st.announced && time.Since(st.down) > offlineGrace {
			st.announced = true
			s.Emit(Event{Kind: NodeOffline, Node: info})
		}
	}
	for id := range s.seen {
		if !live[id] {
			delete(s.seen, id)
		}
	}
}
