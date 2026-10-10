package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"frostbite/internal/compose"
	"frostbite/internal/db"
	"frostbite/internal/keys"
	"frostbite/internal/share"
	"frostbite/internal/spec"
)

// registerUsers registers user management endpoints.
func (s *Server) registerUsers(mux authMux) {
	mux.Auth("GET /users", s.listUsers)
	mux.Auth("GET /quota", s.quota)
	mux.Auth("POST /users", s.createUser)
	mux.Auth("POST /users/batch", s.createUsers)
	mux.Auth("POST /users/import", s.importUsers)
	mux.Auth("POST /users/import-db", s.importDatabase)
	mux.Auth("POST /users/bulk", s.bulkUsers)
	mux.Auth("GET /users/{id}", s.getUser)
	mux.Auth("PUT /users/{id}", s.updateUser)
	mux.Auth("POST /users/{id}/rotate", s.rotateUser)
	mux.Auth("GET /users/{id}/traffic", s.userTraffic)
	mux.Auth("GET /users/{id}/links", s.userLinks)
	mux.Auth("GET /users/{id}/devices", s.userDevices)
	mux.Auth("DELETE /users/{id}/devices/{device}", s.deleteDevice)
}

// userResponse is a user with the extras the UI shows next to it.
type userResponse struct {
	db.User
	SquadIDs []int64 `json:"squad_ids"`
	Online   bool    `json:"online"`
	SubURL   string  `json:"sub_url"`
}

// newUserResponse decorates a user.
func (s *Server) newUserResponse(r *http.Request, u db.User, squads []int64, online map[int64]bool) userResponse {
	return userResponse{User: u, SquadIDs: orEmpty(squads), Online: online[u.ID], SubURL: s.publicURL(r) + "/sub/" + u.SubToken}
}

// onlineSet is the set of users with a live connection.
func (s *Server) onlineSet() map[int64]bool {
	set := map[int64]bool{}
	for _, id := range s.Hub.OnlineUserIDs() {
		set[id] = true
	}
	return set
}

// scopeOwner returns the owner id a request is limited to, nil for admins who see everyone.
func scopeOwner(r *http.Request) *int64 {
	a, _ := AdminFromContext(r.Context())
	if a.Role == RoleReseller {
		return &a.ID
	}
	return nil
}

// canSee reports whether the caller may touch a user.
func canSee(r *http.Request, u db.User) bool {
	owner := scopeOwner(r)
	return owner == nil || (u.OwnerID != nil && *u.OwnerID == *owner)
}

// loadUser fetches the {id} user and enforces ownership, answering the request itself on failure.
func (s *Server) loadUser(w http.ResponseWriter, r *http.Request) (db.User, bool) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return db.User{}, false
	}
	u, err := s.Queries.GetUser(r.Context(), id)
	if err != nil {
		dbError(w, err)
		return db.User{}, false
	}
	if !canSee(r, u) {
		notFound(w, "not found")
		return db.User{}, false
	}
	return u, true
}

// strParam returns a non-empty query value as a pointer.
func strParam(r *http.Request, key string) *string {
	if v := strings.TrimSpace(r.URL.Query().Get(key)); v != "" {
		return &v
	}
	return nil
}

// int64Param returns a numeric query value as a pointer.
func int64Param(r *http.Request, key string) *int64 {
	if n, err := strconv.ParseInt(r.URL.Query().Get(key), 10, 64); err == nil {
		return &n
	}
	return nil
}

// listUsers pages through users with filters.
func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	limit, offset := paging(r, 50, 500)
	owner := scopeOwner(r)
	if owner == nil {
		owner = int64Param(r, "owner")
	}
	rows, err := s.Queries.ListUsers(r.Context(), db.ListUsersParams{
		Status: strParam(r, "status"), Search: strParam(r, "search"), Owner: owner, Tag: strParam(r, "tag"),
		Squad: int64Param(r, "squad"), Sort: r.URL.Query().Get("sort"), Skip: offset, MaxRows: limit,
	})
	if err != nil {
		internalError(w, err)
		return
	}

	ids := make([]int64, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	links, err := s.Queries.ListUserSquadsByUsers(r.Context(), ids)
	if err != nil {
		internalError(w, err)
		return
	}
	squads := map[int64][]int64{}
	for _, l := range links {
		squads[l.UserID] = append(squads[l.UserID], l.SquadID)
	}

	online := s.onlineSet()
	var total int64
	items := make([]userResponse, len(rows))
	for i, row := range rows {
		total = row.Total
		items[i] = s.newUserResponse(r, db.User{
			ID: row.ID, Username: row.Username, Uuid: row.Uuid, Password: row.Password, SubToken: row.SubToken, Status: row.Status,
			TrafficLimit: row.TrafficLimit, TrafficUsed: row.TrafficUsed, TrafficLifetime: row.TrafficLifetime, ResetStrategy: row.ResetStrategy,
			LastReset: row.LastReset, ExpireAt: row.ExpireAt, OnHoldDays: row.OnHoldDays, DeviceLimit: row.DeviceLimit, IpLimit: row.IpLimit,
			Tags: row.Tags, Note: row.Note, Email: row.Email, TelegramID: row.TelegramID, PlanID: row.PlanID, OwnerID: row.OwnerID,
			OnlineAt: row.OnlineAt, BlockedUntil: row.BlockedUntil, SubLastAt: row.SubLastAt, SubLastUa: row.SubLastUa, CreatedAt: row.CreatedAt,
		}, squads[row.ID], online)
	}
	ok(w, map[string]any{"items": items, "total": total})
}

// getUser returns one user.
func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	u, good := s.loadUser(w, r)
	if !good {
		return
	}
	squads, err := s.Queries.ListUserSquadIDs(r.Context(), u.ID)
	if err != nil {
		internalError(w, err)
		return
	}
	ok(w, s.newUserResponse(r, u, squads, s.onlineSet()))
}

// userRequest is the JSON body for creating or editing a user.
type userRequest struct {
	Username        string     `json:"username"`
	Status          string     `json:"status"`
	TrafficLimit    int64      `json:"traffic_limit"`
	ResetStrategy   string     `json:"reset_strategy"`
	ExpireAt        *time.Time `json:"expire_at"`
	DurationDays    int32      `json:"duration_days"`      // create only: expire this many days from now
	StartOnFirstUse bool       `json:"start_on_first_use"` // create only: the clock starts at the first connection
	OnHoldDays      int32      `json:"on_hold_days"`
	DeviceLimit     int32      `json:"device_limit"`
	IPLimit         int32      `json:"ip_limit"`
	Tags            []string   `json:"tags"`
	Note            string     `json:"note"`
	Email           string     `json:"email"`
	TelegramID      *int64     `json:"telegram_id"`
	PlanID          *int64     `json:"plan_id"`
	SquadIDs        []int64    `json:"squad_ids"`
}

// userNamePattern is what a username may look like.
var userNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.@-]{2,64}$`)

// applyPlan fills the blanks of a create request from its plan.
func (s *Server) applyPlan(ctx context.Context, req *userRequest) error {
	if req.PlanID == nil {
		return nil
	}
	p, err := s.Queries.GetPlan(ctx, *req.PlanID)
	if err != nil {
		return fmt.Errorf("the plan does not exist")
	}
	if req.TrafficLimit == 0 {
		req.TrafficLimit = p.TrafficLimit
	}
	if req.ResetStrategy == "" {
		req.ResetStrategy = p.ResetStrategy
	}
	if req.DurationDays == 0 && req.ExpireAt == nil {
		req.DurationDays = p.DurationDays
	}
	req.StartOnFirstUse = req.StartOnFirstUse || p.StartOnFirstUse
	if req.DeviceLimit == 0 {
		req.DeviceLimit = p.DeviceLimit
	}
	if req.IPLimit == 0 {
		req.IPLimit = p.IpLimit
	}
	if len(req.SquadIDs) == 0 {
		req.SquadIDs = p.SquadIds
	}
	return nil
}

// newUserParams turns a create request into insert params with fresh secrets.
func newUserParams(req userRequest, name string, owner *int64) (db.CreateUserParams, error) {
	token, err := keys.Token(16)
	if err != nil {
		return db.CreateUserParams{}, err
	}
	pass, err := keys.Token(18)
	if err != nil {
		return db.CreateUserParams{}, err
	}

	p := db.CreateUserParams{
		Username: name, Uuid: keys.UUID(), Password: pass, SubToken: token, Status: "active", TrafficLimit: req.TrafficLimit,
		ResetStrategy: req.ResetStrategy, ExpireAt: req.ExpireAt, OnHoldDays: req.OnHoldDays, DeviceLimit: req.DeviceLimit,
		IpLimit: req.IPLimit, Tags: orEmpty(req.Tags), Note: req.Note, Email: req.Email, TelegramID: req.TelegramID,
		PlanID: req.PlanID, OwnerID: owner,
	}
	if p.ResetStrategy == "" {
		p.ResetStrategy = "none"
	}
	if req.StartOnFirstUse {
		p.Status = "on_hold"
		if p.OnHoldDays == 0 {
			p.OnHoldDays = req.DurationDays
		}
		p.ExpireAt = nil
	} else if req.ExpireAt == nil && req.DurationDays > 0 {
		t := time.Now().Add(time.Duration(req.DurationDays) * 24 * time.Hour)
		p.ExpireAt = &t
	}
	return p, nil
}

// checkReseller makes sure a reseller stays inside their quotas. adding is how many users are about to appear,
// traffic is the total limit they would hold, and replaces is the limit being swapped out on an edit.
func (s *Server) checkReseller(ctx context.Context, admin db.Admin, adding int, traffic, replaces int64) string {
	if admin.Role != RoleReseller {
		return ""
	}
	t, err := s.Queries.OwnerTotals(ctx, &admin.ID)
	if err != nil {
		return "could not check your quota"
	}
	if admin.UserQuota != nil && t.Users+int64(adding) > int64(*admin.UserQuota) {
		return fmt.Sprintf("you can have at most %d users", *admin.UserQuota)
	}
	if admin.TrafficQuota != nil {
		if adding > 0 && traffic == 0 {
			return "your account needs a traffic limit on every user, unlimited is not allowed"
		}
		if t.Allocated-replaces+traffic > *admin.TrafficQuota {
			left := max(*admin.TrafficQuota-t.Allocated+replaces, 0)
			return fmt.Sprintf("that is more traffic than you have left to give out (%s)", formatBytes(left))
		}
	}
	return ""
}

// formatBytes prints a size for messages.
func formatBytes(n int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	v, i := float64(n), 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

// quota reports how much of their allowance a reseller has used.
func (s *Server) quota(w http.ResponseWriter, r *http.Request) {
	admin, _ := AdminFromContext(r.Context())
	t, err := s.Queries.OwnerTotals(r.Context(), &admin.ID)
	if err != nil {
		internalError(w, err)
		return
	}
	ok(w, map[string]any{
		"users": t.Users, "user_quota": admin.UserQuota, "traffic_allocated": t.Allocated, "traffic_used": t.Used, "traffic_quota": admin.TrafficQuota,
	})
}

// validate checks the parts of a user request that don't depend on the database.
func (req *userRequest) validate() error {
	if req.ResetStrategy != "" && !validReset(req.ResetStrategy) {
		return spec.Invalid("reset_strategy", "reset strategy must be none, day, week, month or year")
	}
	for _, f := range []struct {
		field string
		v     int64
	}{{"traffic_limit", req.TrafficLimit}, {"device_limit", int64(req.DeviceLimit)}, {"ip_limit", int64(req.IPLimit)}, {"duration_days", int64(req.DurationDays)}, {"on_hold_days", int64(req.OnHoldDays)}} {
		if f.v < 0 {
			return spec.Invalid(f.field, "can't be negative")
		}
	}
	if e := strings.TrimSpace(req.Email); e != "" && !strings.Contains(e, "@") {
		return spec.Invalid("email", "that does not look like an email address")
	}
	return nil
}

// createUser adds one user.
func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	admin, _ := AdminFromContext(r.Context())
	var req userRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if !userNamePattern.MatchString(req.Username) {
		invalid(w, "username", "username must be 2-64 characters: letters, digits, dot, dash, underscore or @")
		return
	}
	if err := req.validate(); err != nil {
		badInput(w, err)
		return
	}
	if err := s.applyPlan(r.Context(), &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if msg := s.checkReseller(r.Context(), admin, 1, req.TrafficLimit, 0); msg != "" {
		forbidden(w, msg)
		return
	}

	u, err := s.insertUser(r.Context(), req, req.Username, admin)
	if err != nil {
		dbError(w, err)
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "user.create", u.Username, nil)
	created(w, s.newUserResponse(r, u, req.SquadIDs, nil))
}

// insertUser stores a user and the squads they start in.
func (s *Server) insertUser(ctx context.Context, req userRequest, name string, admin db.Admin) (db.User, error) {
	p, err := newUserParams(req, name, &admin.ID)
	if err != nil {
		return db.User{}, err
	}
	u, err := s.Queries.CreateUser(ctx, p)
	if err != nil {
		return db.User{}, err
	}
	if len(req.SquadIDs) > 0 {
		err = s.Queries.AddUserSquads(ctx, db.AddUserSquadsParams{Ids: []int64{u.ID}, SquadIds: req.SquadIDs})
	}
	return u, err
}

// batchRequest creates many users that share the same settings.
type batchRequest struct {
	userRequest
	Prefix string `json:"prefix"`
	Count  int    `json:"count"`
	Start  int    `json:"start"`
}

// createUsers adds many users at once, named prefix1, prefix2 and so on.
func (s *Server) createUsers(w http.ResponseWriter, r *http.Request) {
	admin, _ := AdminFromContext(r.Context())
	var req batchRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if req.Count < 1 || req.Count > 1000 {
		invalid(w, "count", "count must be between 1 and 1000")
		return
	}
	if !userNamePattern.MatchString(req.Prefix + "00") {
		invalid(w, "prefix", "prefix has characters usernames can't contain")
		return
	}
	if req.Start == 0 {
		req.Start = 1
	}
	if err := req.validate(); err != nil {
		badInput(w, err)
		return
	}
	if err := s.applyPlan(r.Context(), &req.userRequest); err != nil {
		badRequest(w, err.Error())
		return
	}
	if msg := s.checkReseller(r.Context(), admin, req.Count, req.TrafficLimit*int64(req.Count), 0); msg != "" {
		forbidden(w, msg)
		return
	}

	out := make([]db.User, 0, req.Count)
	for i := range req.Count {
		u, err := s.insertUser(r.Context(), req.userRequest, fmt.Sprintf("%s%d", req.Prefix, req.Start+i), admin)
		if err != nil {
			dbError(w, fmt.Errorf("after %d users: %w", len(out), err))
			return
		}
		out = append(out, u)
	}
	s.Hub.MarkDirty()
	s.audit(r, "user.batch", req.Prefix, map[string]any{"count": req.Count})
	base := s.publicURL(r)
	links := make([]string, len(out))
	for i, u := range out {
		links[i] = base + "/sub/" + u.SubToken
	}
	created(w, map[string]any{"users": out, "links": links})
}

// updateUser edits a user.
func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	cur, good := s.loadUser(w, r)
	if !good {
		return
	}
	var req userRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if req.Username = strings.TrimSpace(req.Username); req.Username == "" {
		req.Username = cur.Username
	}
	if !userNamePattern.MatchString(req.Username) {
		invalid(w, "username", "username must be 2-64 characters: letters, digits, dot, dash, underscore or @")
		return
	}
	if req.ResetStrategy == "" {
		req.ResetStrategy = cur.ResetStrategy
	}
	if err := req.validate(); err != nil {
		badInput(w, err)
		return
	}
	if admin, _ := AdminFromContext(r.Context()); admin.Role == RoleReseller && req.TrafficLimit != cur.TrafficLimit {
		if msg := s.checkReseller(r.Context(), admin, 0, req.TrafficLimit, cur.TrafficLimit); msg != "" {
			forbidden(w, msg)
			return
		}
	}
	status := req.Status
	switch status {
	case "":
		status = cur.Status
	case "active", "disabled", "on_hold":
	case "limited", "expired":
		status = cur.Status // these are set by the quota loop, not by hand
	default:
		invalid(w, "status", "status must be active, disabled or on_hold")
		return
	}

	u, err := s.Queries.UpdateUser(r.Context(), db.UpdateUserParams{
		ID: cur.ID, Username: req.Username, Status: status, TrafficLimit: req.TrafficLimit, ResetStrategy: req.ResetStrategy,
		ExpireAt: req.ExpireAt, OnHoldDays: req.OnHoldDays, DeviceLimit: req.DeviceLimit, IpLimit: req.IPLimit, Tags: orEmpty(req.Tags),
		Note: req.Note, Email: req.Email, TelegramID: req.TelegramID, PlanID: req.PlanID,
	})
	if err != nil {
		dbError(w, err)
		return
	}
	ids := []int64{u.ID}
	if err := s.Queries.RefreshUsersStatus(r.Context(), ids); err != nil {
		internalError(w, err)
		return
	}
	if req.SquadIDs != nil {
		if err := s.Queries.ClearUserSquads(r.Context(), ids); err != nil {
			internalError(w, err)
			return
		}
		if len(req.SquadIDs) > 0 {
			if err := s.Queries.AddUserSquads(r.Context(), db.AddUserSquadsParams{Ids: ids, SquadIds: req.SquadIDs}); err != nil {
				dbError(w, err)
				return
			}
		}
	}
	s.Hub.MarkDirty()
	s.audit(r, "user.update", u.Username, nil)

	u, _ = s.Queries.GetUser(r.Context(), u.ID)
	squads, _ := s.Queries.ListUserSquadIDs(r.Context(), u.ID)
	ok(w, s.newUserResponse(r, u, squads, s.onlineSet()))
}

// bulkRequest applies one action to many users.
type bulkRequest struct {
	Action   string   `json:"action"`
	IDs      []int64  `json:"ids"`
	Days     int32    `json:"days"`
	Bytes    int64    `json:"bytes"`
	SquadIDs []int64  `json:"squad_ids"`
	Tags     []string `json:"tags"`
	OwnerID  *int64   `json:"owner_id"`
}

// bulkUsers runs a bulk action.
func (s *Server) bulkUsers(w http.ResponseWriter, r *http.Request) {
	var req bulkRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if len(req.IDs) == 0 {
		badRequest(w, "pick at least one user")
		return
	}

	ids, err := s.allowedIDs(r, req.IDs)
	if err != nil {
		internalError(w, err)
		return
	}
	if len(ids) == 0 {
		notFound(w, "none of those users exist")
		return
	}

	ctx := r.Context()
	switch req.Action {
	case "delete":
		_, err = s.Queries.DeleteUsers(ctx, ids)
	case "enable":
		_, err = s.Queries.SetUsersStatus(ctx, db.SetUsersStatusParams{Ids: ids, Status: "active"})
		if err == nil {
			err = s.Queries.RefreshUsersStatus(ctx, ids)
		}
	case "disable":
		_, err = s.Queries.SetUsersStatus(ctx, db.SetUsersStatusParams{Ids: ids, Status: "disabled"})
	case "reset_traffic":
		err = s.Queries.ResetUsersTraffic(ctx, ids)
	case "extend":
		if req.Days == 0 {
			invalid(w, "days", "days is required")
			return
		}
		err = s.Queries.ExtendUsers(ctx, db.ExtendUsersParams{Ids: ids, Days: req.Days})
		if err == nil {
			err = s.Queries.RefreshUsersStatus(ctx, ids)
		}
	case "add_traffic":
		if admin, _ := AdminFromContext(r.Context()); admin.Role == RoleReseller && req.Bytes > 0 {
			if msg := s.checkReseller(r.Context(), admin, 0, req.Bytes*int64(len(ids)), 0); msg != "" {
				forbidden(w, msg)
				return
			}
		}
		err = s.Queries.AddUsersTraffic(ctx, db.AddUsersTrafficParams{Ids: ids, Bytes: req.Bytes})
		if err == nil {
			err = s.Queries.RefreshUsersStatus(ctx, ids)
		}
	case "set_squads", "add_squads":
		if req.Action == "set_squads" {
			if err = s.Queries.ClearUserSquads(ctx, ids); err != nil {
				break
			}
		}
		if len(req.SquadIDs) > 0 {
			err = s.Queries.AddUserSquads(ctx, db.AddUserSquadsParams{Ids: ids, SquadIds: req.SquadIDs})
		}
	case "add_tags":
		err = s.Queries.AddUsersTags(ctx, db.AddUsersTagsParams{Ids: ids, NewTags: req.Tags})
	case "set_owner":
		if scopeOwner(r) != nil {
			forbidden(w, "resellers can't hand users over")
			return
		}
		err = s.Queries.SetUsersOwner(ctx, db.SetUsersOwnerParams{Ids: ids, OwnerID: req.OwnerID})
	default:
		badRequest(w, "unknown action "+strconv.Quote(req.Action))
		return
	}
	if err != nil {
		dbError(w, err)
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "user.bulk."+req.Action, fmt.Sprintf("%d users", len(ids)), nil)
	ok(w, map[string]int{"affected": len(ids)})
}

// allowedIDs filters ids down to the users the caller may touch.
func (s *Server) allowedIDs(r *http.Request, ids []int64) ([]int64, error) {
	owner := scopeOwner(r)
	rows, err := s.Queries.ListUsers(r.Context(), db.ListUsersParams{Owner: owner, MaxRows: 100000})
	if err != nil {
		return nil, err
	}
	have := map[int64]bool{}
	for _, row := range rows {
		have[row.ID] = true
	}
	var out []int64
	for _, id := range ids {
		if have[id] {
			out = append(out, id)
		}
	}
	return out, nil
}

// rotateUser replaces a user's credentials or subscription link.
func (s *Server) rotateUser(w http.ResponseWriter, r *http.Request) {
	cur, good := s.loadUser(w, r)
	if !good {
		return
	}
	var req struct {
		What string `json:"what"` // secrets or sub
	}
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}

	var u db.User
	var err error
	switch req.What {
	case "secrets":
		pass, e := keys.Token(18)
		if e != nil {
			internalError(w, e)
			return
		}
		u, err = s.Queries.RotateUserSecrets(r.Context(), db.RotateUserSecretsParams{ID: cur.ID, Uuid: keys.UUID(), Password: pass})
	case "sub":
		token, e := keys.Token(16)
		if e != nil {
			internalError(w, e)
			return
		}
		u, err = s.Queries.RotateUserSubToken(r.Context(), db.RotateUserSubTokenParams{ID: cur.ID, SubToken: token})
	default:
		badRequest(w, `what must be "secrets" or "sub"`)
		return
	}
	if err != nil {
		dbError(w, err)
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "user.rotate."+req.What, u.Username, nil)
	squads, _ := s.Queries.ListUserSquadIDs(r.Context(), u.ID)
	ok(w, s.newUserResponse(r, u, squads, s.onlineSet()))
}

// userTraffic returns a user's usage over time.
func (s *Server) userTraffic(w http.ResponseWriter, r *http.Request) {
	u, good := s.loadUser(w, r)
	if !good {
		return
	}
	since := rangeSince(r.URL.Query().Get("range"))
	series, err := s.Queries.TrafficSeries(r.Context(), db.TrafficSeriesParams{Since: since, UserID: &u.ID})
	if err != nil {
		internalError(w, err)
		return
	}
	byNode, err := s.Queries.TrafficByNode(r.Context(), db.TrafficByNodeParams{Since: since, UserID: &u.ID})
	if err != nil {
		internalError(w, err)
		return
	}
	ok(w, map[string]any{"series": orEmpty(series), "by_node": orEmpty(byNode), "online_ips": orEmpty(s.Hub.OnlineIPs(u.ID))})
}

// linkResponse is one importable connection.
type linkResponse struct {
	Name     string `json:"name"`
	Node     string `json:"node"`
	Country  string `json:"country"`
	Protocol string `json:"protocol"`
	Bridge   bool   `json:"bridge"`
	Link     string `json:"link"`
	Config   string `json:"config,omitempty"` // a ready to use config file, for protocols that have one
}

// newLinkResponse builds the response for one profile.
func newLinkResponse(p compose.Profile) (linkResponse, bool) {
	l, err := share.Link(p.Upstream)
	if err != nil {
		return linkResponse{}, false
	}
	r := linkResponse{Name: p.Name, Node: p.NodeName, Country: p.Country, Protocol: p.Protocol, Bridge: p.Bridge, Link: l}
	if p.Protocol == spec.ProtoWireGuard {
		r.Config = share.WGQuick(p.Upstream, p.Options.WGDNS)
	}
	return r, true
}

// userLinks lists the share links of a user's connections.
func (s *Server) userLinks(w http.ResponseWriter, r *http.Request) {
	u, good := s.loadUser(w, r)
	if !good {
		return
	}
	profiles, err := s.profilesOf(r.Context(), u)
	if err != nil {
		internalError(w, err)
		return
	}
	out := make([]linkResponse, 0, len(profiles))
	for _, p := range profiles {
		if r, ok := newLinkResponse(p); ok {
			out = append(out, r)
		}
	}
	ok(w, map[string]any{"sub_url": s.publicURL(r) + "/sub/" + u.SubToken, "links": out})
}

// userDevices lists the devices that fetched a user's subscription.
func (s *Server) userDevices(w http.ResponseWriter, r *http.Request) {
	u, good := s.loadUser(w, r)
	if !good {
		return
	}
	rows, err := s.Queries.ListDevices(r.Context(), u.ID)
	if err != nil {
		internalError(w, err)
		return
	}
	ok(w, orEmpty(rows))
}

// deleteDevice forgets a device, freeing a slot under the device limit.
func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	u, good := s.loadUser(w, r)
	if !good {
		return
	}
	dev, err := strconv.ParseInt(r.PathValue("device"), 10, 64)
	if err != nil {
		badRequest(w, "invalid device id")
		return
	}
	rows, err := s.Queries.DeleteDevice(r.Context(), db.DeleteDeviceParams{ID: dev, UserID: u.ID})
	if err != nil {
		internalError(w, err)
		return
	}
	if rows == 0 {
		notFound(w, "not found")
		return
	}
	noContent(w)
}

// userByToken finds a user from a subscription token.
func (s *Server) userByToken(ctx context.Context, token string) (db.User, error) {
	u, err := s.Queries.GetUserBySubToken(ctx, token)
	if errors.Is(err, pgx.ErrNoRows) {
		return db.User{}, err
	}
	return u, err
}
