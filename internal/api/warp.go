package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"frostbite/internal/metrics"
	"frostbite/internal/warp"
)

// registerWarp registers the Cloudflare WARP account endpoints.
func (s *Server) registerWarp(mux authMux) {
	mux.Admin("GET /warp", s.getWarp)
	mux.Admin("POST /warp/register", s.registerWarpAccount)
	mux.Admin("PUT /warp/license", s.setWarpLicense)
	mux.Admin("DELETE /warp", s.deleteWarp)
}

// warpView is the account without anything secret.
type warpView struct {
	Registered bool       `json:"registered"`
	Type       string     `json:"type,omitempty"`
	License    string     `json:"license,omitempty"`
	AddressV4  string     `json:"address_v4,omitempty"`
	AddressV6  string     `json:"address_v6,omitempty"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
}

// loadWarp reads the stored account, if there is one.
func (s *Server) loadWarp(ctx context.Context) (*warp.Account, error) {
	var a warp.Account
	raw, err := s.Queries.GetSetting(ctx, "warp")
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, err
	}
	if a.PrivateKey == "" {
		return nil, nil
	}
	return &a, nil
}

// viewOf hides secrets.
func viewOf(a *warp.Account) warpView {
	if a == nil {
		return warpView{}
	}
	lic := a.License
	if len(lic) > 6 {
		lic = lic[:3] + "…" + lic[len(lic)-3:]
	}
	return warpView{Registered: true, Type: a.Type, License: lic, AddressV4: a.AddressV4, AddressV6: a.AddressV6, CreatedAt: &a.CreatedAt}
}

// getWarp reports the account state.
func (s *Server) getWarp(w http.ResponseWriter, r *http.Request) {
	a, err := s.loadWarp(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	ok(w, viewOf(a))
}

// registerWarpAccount creates the account, replacing a previous one when asked to.
func (s *Server) registerWarpAccount(w http.ResponseWriter, r *http.Request) {
	cur, err := s.loadWarp(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	if cur != nil && r.URL.Query().Get("replace") != "1" {
		conflict(w, "there is already a WARP account, replace it to get a new identity")
		return
	}
	acc, err := s.warpClient().Register(r.Context())
	metrics.WarpOperations.WithLabelValues("register", metrics.Result(err)).Inc()
	if err != nil {
		fail(w, http.StatusBadGateway, "cloudflare", err.Error())
		return
	}
	if err := s.saveSetting(r.Context(), "warp", acc); err != nil {
		internalError(w, err)
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "warp.register", acc.ID, nil)
	ok(w, viewOf(&acc))
}

// setWarpLicense attaches a WARP+ key.
func (s *Server) setWarpLicense(w http.ResponseWriter, r *http.Request) {
	var req struct {
		License string `json:"license"`
	}
	if err := decode(r, &req); err != nil || strings.TrimSpace(req.License) == "" {
		badRequest(w, "license is required")
		return
	}
	cur, err := s.loadWarp(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	if cur == nil {
		conflict(w, "register a WARP account first")
		return
	}
	acc, err := s.warpClient().SetLicense(r.Context(), *cur, strings.TrimSpace(req.License))
	metrics.WarpOperations.WithLabelValues("license", metrics.Result(err)).Inc()
	if err != nil {
		fail(w, http.StatusBadGateway, "cloudflare", err.Error())
		return
	}
	if err := s.saveSetting(r.Context(), "warp", acc); err != nil {
		internalError(w, err)
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "warp.license", acc.ID, nil)
	ok(w, viewOf(&acc))
}

// deleteWarp forgets the account. Outbounds that used it make their daemons reject the next spec until a new one exists.
func (s *Server) deleteWarp(w http.ResponseWriter, r *http.Request) {
	if err := s.saveSetting(r.Context(), "warp", warp.Account{}); err != nil {
		internalError(w, err)
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "warp.delete", "", nil)
	noContent(w)
}

// warpClient returns the client, which tests can replace.
func (s *Server) warpClient() *warp.Client {
	if s.Warp != nil {
		return s.Warp
	}
	return warp.New()
}
