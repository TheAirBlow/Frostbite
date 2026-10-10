// Package quota enforces expiry, traffic limits, resets and on-hold activation.
package quota

import (
	"context"
	"log/slog"
	"time"

	"frostbite/internal/db"
	"frostbite/internal/metrics"
)

// keepTraffic is how long hourly traffic rows are kept.
const keepTraffic = 400 * 24 * time.Hour

// Hooks are called when a pass changes things. Any of them may be nil.
type Hooks struct {
	Dirty   func()            // who may connect changed
	Expired func(ids []int64) // users that just expired
	Limited func(ids []int64) // users that just hit their traffic limit
}

// Result says what a pass did.
type Result struct {
	Changed bool
	Expired []int64
	Limited []int64
}

// Run checks every user on an interval until ctx ends.
func Run(ctx context.Context, q *db.Queries, h Hooks, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	housekeeping := time.NewTicker(time.Hour)
	defer housekeeping.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			r := Pass(ctx, q)
			if r.Changed && h.Dirty != nil {
				h.Dirty()
			}
			if len(r.Expired) > 0 && h.Expired != nil {
				h.Expired(r.Expired)
			}
			if len(r.Limited) > 0 && h.Limited != nil {
				h.Limited(r.Limited)
			}
		case <-housekeeping.C:
			err := q.DeleteExpiredSessions(ctx)
			metrics.Housekeeping.WithLabelValues("sessions", metrics.Result(err)).Inc()
			if err != nil {
				slog.Warn("quota: pruning sessions failed", "err", err)
			}
			err = q.PruneTraffic(ctx, time.Now().Add(-keepTraffic))
			metrics.Housekeeping.WithLabelValues("traffic", metrics.Result(err)).Inc()
			if err != nil {
				slog.Warn("quota: pruning traffic failed", "err", err)
			}
		}
	}
}

// Pass runs every check once and reports what changed.
func Pass(ctx context.Context, q *db.Queries) Result {
	defer func(start time.Time) {
		metrics.QuotaPasses.Inc()
		metrics.QuotaPassSeconds.Observe(time.Since(start).Seconds())
	}(time.Now())
	var res Result
	note := func(what string, ids []int64, err error) {
		if err != nil {
			metrics.QuotaErrors.WithLabelValues(what).Inc()
			slog.Error("quota: "+what+" failed", "err", err)
			return
		}
		if len(ids) > 0 {
			metrics.QuotaChanges.WithLabelValues(what).Add(float64(len(ids)))
			slog.Info("quota: "+what, "users", len(ids))
			res.Changed = true
		}
	}

	// Resets go first so a user who is due one is not limited a moment before.
	ids, err := q.ResetDueUsers(ctx)
	note("traffic reset", ids, err)
	ids, err = q.ActivateOnHold(ctx)
	note("on-hold users activated", ids, err)
	ids, err = q.ExpireUsers(ctx)
	note("users expired", ids, err)
	res.Expired = ids
	ids, err = q.LimitUsers(ctx)
	note("users limited", ids, err)
	res.Limited = ids
	ids, err = q.ClearExpiredBlocks(ctx)
	note("ip-limit blocks lifted", ids, err)
	return res
}
