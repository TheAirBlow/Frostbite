package api

import (
	"net/http"
	"strings"

	"frostbite/internal/db"
	"frostbite/internal/spec"
)

// registerAdmins registers the endpoints for managing panel accounts.
func (s *Server) registerAdmins(mux authMux) {
	mux.Owner("GET /admins", s.listAdmins)
	mux.Owner("POST /admins", s.createAdmin)
	mux.Owner("PUT /admins/{id}", s.updateAdmin)
	mux.Owner("PUT /admins/{id}/password", s.resetAdminPassword)
	mux.Owner("DELETE /admins/{id}", s.deleteAdmin)
	mux.Owner("GET /audit", s.listAudit)
}

// adminRequest is the JSON body for creating or editing an admin.
type adminRequest struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	Role         string `json:"role"`
	Enabled      *bool  `json:"enabled"`
	UserQuota    *int32 `json:"user_quota"`
	TrafficQuota *int64 `json:"traffic_quota"`
	Note         string `json:"note"`
}

// validRole reports whether role is one of the three known roles.
func validRole(role string) bool {
	return role == RoleOwner || role == RoleAdmin || role == RoleReseller
}

// listAdmins lists every panel account.
func (s *Server) listAdmins(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Queries.ListAdmins(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	out := make([]adminResponse, len(rows))
	for i, a := range rows {
		out[i] = newAdminResponse(a)
	}
	ok(w, out)
}

// checkQuotas refuses quotas below zero.
func (req adminRequest) checkQuotas() error {
	if req.UserQuota != nil && *req.UserQuota < 0 {
		return spec.Invalid("user_quota", "can't be negative")
	}
	if req.TrafficQuota != nil && *req.TrafficQuota < 0 {
		return spec.Invalid("traffic_quota", "can't be negative")
	}
	return nil
}

// createAdmin adds a panel account.
func (s *Server) createAdmin(w http.ResponseWriter, r *http.Request) {
	var req adminRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	if !usernamePattern.MatchString(req.Username) {
		invalid(w, "username", "username must be 2-32 characters: lowercase letters, digits, dot, dash or underscore")
		return
	}
	if len(req.Password) < 8 {
		invalid(w, "password", "the password must be at least 8 characters")
		return
	}
	if err := req.checkQuotas(); err != nil {
		badInput(w, err)
		return
	}
	if req.Role == "" {
		req.Role = RoleAdmin
	}
	if !validRole(req.Role) {
		invalid(w, "role", "role must be owner, admin or reseller")
		return
	}

	hash, err := HashPassword(req.Password)
	if err != nil {
		internalError(w, err)
		return
	}
	a, err := s.Queries.CreateAdmin(r.Context(), db.CreateAdminParams{
		Username: req.Username, PasswordHash: hash, Role: req.Role, UserQuota: req.UserQuota, TrafficQuota: req.TrafficQuota, Note: req.Note,
	})
	if err != nil {
		dbError(w, err)
		return
	}
	s.audit(r, "admin.create", a.Username, map[string]any{"role": a.Role})
	created(w, newAdminResponse(a))
}

// updateAdmin edits an account's role, limits and state.
func (s *Server) updateAdmin(w http.ResponseWriter, r *http.Request) {
	me, _ := AdminFromContext(r.Context())
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	var req adminRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if !validRole(req.Role) {
		invalid(w, "role", "role must be owner, admin or reseller")
		return
	}
	if err := req.checkQuotas(); err != nil {
		badInput(w, err)
		return
	}
	enabled := req.Enabled == nil || *req.Enabled
	if id == me.ID && (!enabled || req.Role != RoleOwner) {
		invalid(w, "role", "you can't demote or disable your own account")
		return
	}

	a, err := s.Queries.UpdateAdmin(r.Context(), db.UpdateAdminParams{
		ID: id, Role: req.Role, Enabled: enabled, UserQuota: req.UserQuota, TrafficQuota: req.TrafficQuota, Note: req.Note,
	})
	if err != nil {
		dbError(w, err)
		return
	}
	s.audit(r, "admin.update", a.Username, map[string]any{"role": a.Role, "enabled": a.Enabled})
	ok(w, newAdminResponse(a))
}

// resetAdminPassword sets a new password for another account.
func (s *Server) resetAdminPassword(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	var req passwordRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if len(req.New) < 8 {
		invalid(w, "new", "the new password must be at least 8 characters")
		return
	}
	hash, err := HashPassword(req.New)
	if err != nil {
		internalError(w, err)
		return
	}
	if err := s.Queries.UpdateAdminPassword(r.Context(), db.UpdateAdminPasswordParams{ID: id, PasswordHash: hash}); err != nil {
		internalError(w, err)
		return
	}
	s.audit(r, "admin.password", r.PathValue("id"), nil)
	noContent(w)
}

// deleteAdmin removes an account. Their users stay, ownerless.
func (s *Server) deleteAdmin(w http.ResponseWriter, r *http.Request) {
	me, _ := AdminFromContext(r.Context())
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	if id == me.ID {
		badRequest(w, "you can't delete your own account")
		return
	}
	rows, err := s.Queries.DeleteAdmin(r.Context(), id)
	if err != nil {
		internalError(w, err)
		return
	}
	if rows == 0 {
		notFound(w, "not found")
		return
	}
	s.audit(r, "admin.delete", r.PathValue("id"), nil)
	noContent(w)
}

// listAudit pages through the audit log, newest first.
func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	limit, offset := paging(r, 50, 200)
	rows, err := s.Queries.ListAudit(r.Context(), db.ListAuditParams{Limit: limit, Offset: offset})
	if err != nil {
		internalError(w, err)
		return
	}
	ok(w, orEmpty(rows))
}
