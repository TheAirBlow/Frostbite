// Package api serves the panel's REST API.
package api

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"frostbite/internal/common"
	"frostbite/internal/db"
	"frostbite/internal/hub"
	"frostbite/internal/link"
	"frostbite/internal/notify"
	"frostbite/internal/warp"
)

// Server holds the dependencies every REST handler needs.
type Server struct {
	Queries *db.Queries
	Config  common.Config
	Hub     *hub.Hub
	Pool    *pgxpool.Pool
	Notify  *notify.Service
	Warp    *warp.Client // nil uses the real api

	topo topoCache
}

// Register mounts every panel route onto mux.
func (s *Server) Register(mux *http.ServeMux) {
	api := authMux{ServeMux: http.NewServeMux(), server: s}
	s.registerAuth(api)
	s.registerAdmins(api)
	s.registerDashboard(api)
	s.registerNodes(api)
	s.registerInbounds(api)
	s.registerRouting(api)
	s.registerBridges(api)
	s.registerAccess(api)
	s.registerUsers(api)
	s.registerSettings(api)
	s.registerTools(api)
	s.registerBackup(api)
	s.registerWarp(api)
	s.registerSub(api)
	api.HandleFunc("GET /health", s.health)
	mux.Handle("/api/", http.StripPrefix("/api", api))
	mux.Handle(link.Path, s.Hub.Handler())
	s.registerPublicSub(mux)
	registerNodeFiles(mux)
}

// health returns a successful health report.
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ok(w, map[string]string{"status": "ok"})
}
