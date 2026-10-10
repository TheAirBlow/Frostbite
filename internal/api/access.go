package api

import (
	"net/http"
	"strings"

	"frostbite/internal/db"
)

// registerAccess registers squad and plan endpoints.
func (s *Server) registerAccess(mux authMux) {
	mux.Auth("GET /squads", s.listSquads)
	mux.Admin("POST /squads", s.createSquad)
	mux.Admin("PUT /squads/{id}", s.updateSquad)
	mux.Admin("DELETE /squads/{id}", s.deleteSquad)
	mux.Auth("GET /plans", s.listPlans)
	mux.Admin("POST /plans", s.createPlan)
	mux.Admin("PUT /plans/{id}", s.updatePlan)
	mux.Admin("DELETE /plans/{id}", s.deletePlan)
}

// squadResponse is a squad with the inbounds it grants and how many users hold it.
type squadResponse struct {
	db.Squad
	InboundIDs []int64 `json:"inbound_ids"`
	Users      int     `json:"users"`
}

// listSquads lists squads.
func (s *Server) listSquads(w http.ResponseWriter, r *http.Request) {
	squads, err := s.Queries.ListSquads(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	links, err := s.Queries.ListSquadInbounds(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	members, err := s.Queries.ListUserSquads(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}

	inbounds := map[int64][]int64{}
	for _, l := range links {
		inbounds[l.SquadID] = append(inbounds[l.SquadID], l.InboundID)
	}
	users := map[int64]int{}
	for _, m := range members {
		users[m.SquadID]++
	}
	out := make([]squadResponse, len(squads))
	for i, sq := range squads {
		out[i] = squadResponse{Squad: sq, InboundIDs: orEmpty(inbounds[sq.ID]), Users: users[sq.ID]}
	}
	ok(w, out)
}

// squadRequest is the JSON body for creating or editing a squad.
type squadRequest struct {
	Name       string  `json:"name"`
	Note       string  `json:"note"`
	InboundIDs []int64 `json:"inbound_ids"`
}

// createSquad adds a squad.
func (s *Server) createSquad(w http.ResponseWriter, r *http.Request) {
	var req squadRequest
	if err := decode(r, &req); err != nil || strings.TrimSpace(req.Name) == "" {
		badRequest(w, "name is required")
		return
	}
	sq, err := s.Queries.CreateSquad(r.Context(), db.CreateSquadParams{Name: strings.TrimSpace(req.Name), Note: req.Note})
	if err != nil {
		dbError(w, err)
		return
	}
	if err := s.setSquadInbounds(r, sq.ID, req.InboundIDs); err != nil {
		dbError(w, err)
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "squad.create", sq.Name, nil)
	created(w, squadResponse{Squad: sq, InboundIDs: orEmpty(req.InboundIDs)})
}

// updateSquad edits a squad.
func (s *Server) updateSquad(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	var req squadRequest
	if err := decode(r, &req); err != nil || strings.TrimSpace(req.Name) == "" {
		badRequest(w, "name is required")
		return
	}
	sq, err := s.Queries.UpdateSquad(r.Context(), db.UpdateSquadParams{ID: id, Name: strings.TrimSpace(req.Name), Note: req.Note})
	if err != nil {
		dbError(w, err)
		return
	}
	if err := s.setSquadInbounds(r, id, req.InboundIDs); err != nil {
		dbError(w, err)
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "squad.update", sq.Name, nil)
	ok(w, squadResponse{Squad: sq, InboundIDs: orEmpty(req.InboundIDs)})
}

// setSquadInbounds replaces the inbounds a squad grants.
func (s *Server) setSquadInbounds(r *http.Request, squadID int64, ids []int64) error {
	if err := s.Queries.ClearSquadInbounds(r.Context(), squadID); err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	return s.Queries.AddSquadInbounds(r.Context(), db.AddSquadInboundsParams{SquadID: squadID, InboundIds: ids})
}

// deleteSquad removes a squad. Users keep existing but lose what it granted.
func (s *Server) deleteSquad(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	rows, err := s.Queries.DeleteSquad(r.Context(), id)
	if err != nil {
		dbError(w, err)
		return
	}
	if rows == 0 {
		notFound(w, "not found")
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "squad.delete", r.PathValue("id"), nil)
	noContent(w)
}

// planRequest is the JSON body for creating or editing a plan.
type planRequest struct {
	Name            string  `json:"name"`
	TrafficLimit    int64   `json:"traffic_limit"`
	DurationDays    int32   `json:"duration_days"`
	ResetStrategy   string  `json:"reset_strategy"`
	StartOnFirstUse bool    `json:"start_on_first_use"`
	DeviceLimit     int32   `json:"device_limit"`
	IPLimit         int32   `json:"ip_limit"`
	SquadIDs        []int64 `json:"squad_ids"`
	Note            string  `json:"note"`
}

// clean validates a plan request.
func (p *planRequest) clean() string {
	p.Name = strings.TrimSpace(p.Name)
	if p.ResetStrategy == "" {
		p.ResetStrategy = "none"
	}
	switch {
	case p.Name == "":
		return "name is required"
	case !validReset(p.ResetStrategy):
		return "reset strategy must be none, day, week, month or year"
	case p.TrafficLimit < 0 || p.DurationDays < 0 || p.DeviceLimit < 0 || p.IPLimit < 0:
		return "limits can't be negative"
	}
	return ""
}

// validReset reports whether s is a known reset strategy.
func validReset(s string) bool {
	switch s {
	case "none", "day", "week", "month", "year":
		return true
	}
	return false
}

// listPlans lists plans.
func (s *Server) listPlans(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Queries.ListPlans(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	ok(w, orEmpty(rows))
}

// createPlan adds a plan.
func (s *Server) createPlan(w http.ResponseWriter, r *http.Request) {
	var req planRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if msg := req.clean(); msg != "" {
		badRequest(w, msg)
		return
	}
	p, err := s.Queries.CreatePlan(r.Context(), db.CreatePlanParams{
		Name: req.Name, TrafficLimit: req.TrafficLimit, DurationDays: req.DurationDays, ResetStrategy: req.ResetStrategy,
		StartOnFirstUse: req.StartOnFirstUse, DeviceLimit: req.DeviceLimit, IpLimit: req.IPLimit, SquadIds: orEmpty(req.SquadIDs), Note: req.Note,
	})
	if err != nil {
		dbError(w, err)
		return
	}
	s.audit(r, "plan.create", p.Name, nil)
	created(w, p)
}

// updatePlan edits a plan.
func (s *Server) updatePlan(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	var req planRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if msg := req.clean(); msg != "" {
		badRequest(w, msg)
		return
	}
	p, err := s.Queries.UpdatePlan(r.Context(), db.UpdatePlanParams{
		ID: id, Name: req.Name, TrafficLimit: req.TrafficLimit, DurationDays: req.DurationDays, ResetStrategy: req.ResetStrategy,
		StartOnFirstUse: req.StartOnFirstUse, DeviceLimit: req.DeviceLimit, IpLimit: req.IPLimit, SquadIds: orEmpty(req.SquadIDs), Note: req.Note,
	})
	if err != nil {
		dbError(w, err)
		return
	}
	s.audit(r, "plan.update", p.Name, nil)
	ok(w, p)
}

// deletePlan removes a plan. Users created from it keep their limits.
func (s *Server) deletePlan(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	rows, err := s.Queries.DeletePlan(r.Context(), id)
	if err != nil {
		dbError(w, err)
		return
	}
	if rows == 0 {
		notFound(w, "not found")
		return
	}
	s.audit(r, "plan.delete", r.PathValue("id"), nil)
	noContent(w)
}
