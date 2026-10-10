package api

import (
	"net/http"
	"time"

	"frostbite/internal/db"
)

// registerDashboard registers the overview endpoint.
func (s *Server) registerDashboard(mux authMux) {
	mux.Admin("GET /dashboard", s.dashboard)
}

// rangeSince maps a range name to the start of the window.
func rangeSince(name string) time.Time {
	switch name {
	case "7d":
		return time.Now().Add(-7 * 24 * time.Hour)
	case "30d":
		return time.Now().Add(-30 * 24 * time.Hour)
	}
	return time.Now().Add(-24 * time.Hour)
}

// dashboard collects the numbers shown on the home page.
func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	since := rangeSince(r.URL.Query().Get("range"))

	counts, err := s.Queries.CountUsersByStatus(ctx)
	if err != nil {
		internalError(w, err)
		return
	}
	byStatus := map[string]int64{}
	var total int64
	for _, c := range counts {
		byStatus[c.Status] = c.Count
		total += c.Count
	}
	online := len(s.Hub.OnlineUserIDs())

	series, err := s.Queries.TrafficSeries(ctx, db.TrafficSeriesParams{Since: since})
	if err != nil {
		internalError(w, err)
		return
	}
	var up, down int64
	for _, p := range series {
		up += p.Up
		down += p.Down
	}
	byNode, err := s.Queries.TrafficByNode(ctx, db.TrafficByNodeParams{Since: since})
	if err != nil {
		internalError(w, err)
		return
	}
	top, err := s.Queries.TopUsers(ctx, db.TopUsersParams{Hour: since, Limit: 8})
	if err != nil {
		internalError(w, err)
		return
	}

	daemons, err := s.Queries.ListDaemons(ctx)
	if err != nil {
		internalError(w, err)
		return
	}
	daemonsOnline := 0
	for _, d := range daemons {
		if s.Hub.Status(d.ID).Online {
			daemonsOnline++
		}
	}

	ok(w, map[string]any{
		"users":   map[string]any{"total": total, "online": online, "by_status": byStatus},
		"traffic": map[string]any{"series": orEmpty(series), "up": up, "down": down, "by_node": orEmpty(byNode)},
		"top":     orEmpty(top),
		"daemons": map[string]any{"total": len(daemons), "online": daemonsOnline},
	})
}
