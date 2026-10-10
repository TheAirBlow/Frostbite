package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"frostbite/internal/core"
	"frostbite/internal/db"
	"frostbite/internal/hub"
	"frostbite/internal/link"
	"frostbite/internal/spec"
	"frostbite/node"
)

// registerNodes registers node and daemon management endpoints.
func (s *Server) registerNodes(mux authMux) {
	mux.Admin("GET /nodes", s.listNodes)
	mux.Admin("POST /nodes", s.createNode)
	mux.Admin("PUT /nodes/{id}", s.updateNode)
	mux.Admin("DELETE /nodes/{id}", s.deleteNode)
	mux.Admin("POST /nodes/{id}/daemons", s.createDaemon)
	mux.Admin("PUT /daemons/{id}", s.updateDaemon)
	mux.Admin("DELETE /daemons/{id}", s.deleteDaemon)
	mux.Admin("POST /daemons/{id}/rotate", s.rotateDaemon)
	mux.Admin("POST /daemons/{id}/restart", s.restartDaemon)
	mux.Admin("GET /daemons/{id}/preview", s.previewDaemon)
	mux.Admin("GET /daemons/{id}/logs", s.daemonLogs)
	mux.Auth("GET /cores", s.listCores)
}

// daemonResponse is a daemon with its live state, minus the token hash.
type daemonResponse struct {
	ID            int64           `json:"id"`
	NodeID        int64           `json:"node_id"`
	Kind          string          `json:"kind"`
	Name          string          `json:"name"`
	Enabled       bool            `json:"enabled"`
	DesiredRev    int64           `json:"desired_rev"`
	AppliedRev    int64           `json:"applied_rev"`
	LastError     string          `json:"last_error"`
	LastSeen      *time.Time      `json:"last_seen"`
	CoreVersion   string          `json:"core_version"`
	AgentVersion  string          `json:"agent_version"`
	HostInfo      json.RawMessage `json:"host_info"`
	LogLevel      string          `json:"log_level"`
	DNSServers    []string        `json:"dns_servers"`
	DNSStrategy   string          `json:"dns_strategy"`
	FinalOutbound string          `json:"final_outbound"`
	RawPatch      json.RawMessage `json:"raw_patch"`
	EdgeListen    []string        `json:"edge_listen"`
	EdgeDefault   string          `json:"edge_default"`
	Live          hub.Live        `json:"live"`
}

// newDaemonResponse builds a daemonResponse with live state from the hub.
func (s *Server) newDaemonResponse(d db.Daemon) daemonResponse {
	return daemonResponse{
		ID: d.ID, NodeID: d.NodeID, Kind: d.Kind, Name: d.Name, Enabled: d.Enabled, DesiredRev: d.DesiredRev, AppliedRev: d.AppliedRev,
		LastError: d.LastError, LastSeen: d.LastSeen, CoreVersion: d.CoreVersion, AgentVersion: d.AgentVersion, HostInfo: d.HostInfo,
		LogLevel: d.LogLevel, DNSServers: d.DnsServers, DNSStrategy: d.DnsStrategy, FinalOutbound: d.FinalOutbound, RawPatch: d.RawPatch, EdgeListen: d.EdgeListen, EdgeDefault: d.EdgeDefault,
		Live: s.Hub.Status(d.ID),
	}
}

// nodeResponse is a node with its daemons.
type nodeResponse struct {
	db.Node
	Daemons []daemonResponse `json:"daemons"`
}

// listNodes lists nodes with their daemons and live state.
func (s *Server) listNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.Queries.ListNodes(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	daemons, err := s.Queries.ListDaemons(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}

	out := make([]nodeResponse, len(nodes))
	idx := map[int64]int{}
	for i, n := range nodes {
		out[i] = nodeResponse{Node: n, Daemons: []daemonResponse{}}
		idx[n.ID] = i
	}
	for _, d := range daemons {
		if i, found := idx[d.NodeID]; found {
			out[i].Daemons = append(out[i].Daemons, s.newDaemonResponse(d))
		}
	}
	ok(w, out)
}

// nodeRequest is the JSON body for creating or editing a node.
type nodeRequest struct {
	Name              string   `json:"name"`
	Address           string   `json:"address"`
	Country           string   `json:"country"`
	Tags              []string `json:"tags"`
	TrafficMultiplier *float64 `json:"traffic_multiplier"`
	TrafficLimit      int64    `json:"traffic_limit"`
	Note              string   `json:"note"`
	Enabled           *bool    `json:"enabled"`
	Sort              int32    `json:"sort"`
}

// clean validates a node request and fills defaults.
func (n *nodeRequest) clean() error {
	n.Name, n.Address = strings.TrimSpace(n.Name), strings.TrimSpace(n.Address)
	n.Country = strings.ToUpper(strings.TrimSpace(n.Country))
	switch {
	case n.Name == "":
		return spec.Invalid("name", "name is required")
	case n.Address == "":
		return spec.Invalid("address", "address is required, it is what clients will connect to")
	case strings.ContainsAny(n.Address, " /\\") || strings.Contains(n.Address, "://"):
		return spec.Invalid("address", "use a bare domain or IP address, without a scheme, path or spaces")
	case len(n.Country) > 2:
		return spec.Invalid("country", "country must be a two letter code")
	case n.TrafficMultiplier != nil && *n.TrafficMultiplier < 0:
		return spec.Invalid("traffic_multiplier", "traffic multiplier can't be negative")
	case n.TrafficLimit < 0:
		return spec.Invalid("traffic_limit", "traffic limit can't be negative")
	}
	return nil
}

// createNode adds a node.
func (s *Server) createNode(w http.ResponseWriter, r *http.Request) {
	var req nodeRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if err := req.clean(); err != nil {
		badInput(w, err)
		return
	}
	mult := 1.0
	if req.TrafficMultiplier != nil {
		mult = *req.TrafficMultiplier
	}
	n, err := s.Queries.CreateNode(r.Context(), db.CreateNodeParams{
		Name: req.Name, Address: req.Address, Country: req.Country, Tags: orEmpty(req.Tags), TrafficMultiplier: mult,
		TrafficLimit: req.TrafficLimit, Note: req.Note, Enabled: req.Enabled == nil || *req.Enabled, Sort: req.Sort,
	})
	if err != nil {
		dbError(w, err)
		return
	}
	s.audit(r, "node.create", n.Name, nil)
	created(w, nodeResponse{Node: n, Daemons: []daemonResponse{}})
}

// updateNode edits a node.
func (s *Server) updateNode(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	var req nodeRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if err := req.clean(); err != nil {
		badInput(w, err)
		return
	}
	mult := 1.0
	if req.TrafficMultiplier != nil {
		mult = *req.TrafficMultiplier
	}
	n, err := s.Queries.UpdateNode(r.Context(), db.UpdateNodeParams{
		ID: id, Name: req.Name, Address: req.Address, Country: req.Country, Tags: orEmpty(req.Tags), TrafficMultiplier: mult,
		TrafficLimit: req.TrafficLimit, Note: req.Note, Enabled: req.Enabled == nil || *req.Enabled, Sort: req.Sort,
	})
	if err != nil {
		dbError(w, err)
		return
	}
	if err := s.syncBridges(r.Context()); err != nil {
		internalError(w, err)
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "node.update", n.Name, nil)
	ok(w, n)
}

// deleteNode removes a node and everything running on it.
func (s *Server) deleteNode(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	daemons, err := s.Queries.ListDaemons(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	rows, err := s.Queries.DeleteNode(r.Context(), id)
	if err != nil {
		dbError(w, err)
		return
	}
	if rows == 0 {
		notFound(w, "not found")
		return
	}
	for _, d := range daemons {
		if d.NodeID == id {
			s.Hub.Kick(d.ID)
		}
	}
	s.Hub.MarkDirty()
	s.audit(r, "node.delete", strconv.FormatInt(id, 10), nil)
	noContent(w)
}

// daemonRequest is the JSON body for creating or editing a daemon.
type daemonRequest struct {
	Kind          string          `json:"kind"`
	Name          string          `json:"name"`
	Enabled       *bool           `json:"enabled"`
	LogLevel      string          `json:"log_level"`
	DNSServers    []string        `json:"dns_servers"`
	DNSStrategy   string          `json:"dns_strategy"`
	FinalOutbound string          `json:"final_outbound"`
	RawPatch      json.RawMessage `json:"raw_patch"`
	EdgeListen    []string        `json:"edge_listen"`
	EdgeDefault   *string         `json:"edge_default"`
}

// enrollment is what the admin copies onto the node. The token is shown only here.
type enrollment struct {
	Token   string `json:"token"`
	Env     string `json:"env"`
	Command string `json:"command"`
}

// tokenVar is the env var the node compose file reads a daemon's token from.
func tokenVar(kind string) string { return "FROSTBITE_" + strings.ToUpper(kind) + "_TOKEN" }

// publicURL works out how daemons and users should reach the panel.
func (s *Server) publicURL(r *http.Request) string {
	if u := strings.TrimRight(s.Config.Server.PublicURL, "/"); u != "" {
		return u
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host
}

// newEnrollment builds the copy-paste snippet for a daemon.
func (s *Server) newEnrollment(r *http.Request, kind, token string) enrollment {
	base := s.publicURL(r)
	env := fmt.Sprintf("FROSTBITE_PANEL_URL=%s\n%s=%s\n", base, tokenVar(kind), token)
	cmd := fmt.Sprintf(
		"mkdir -p frostbite-node && cd frostbite-node && curl -fsSL %s/node/docker-compose.yml -o docker-compose.yml && printf '%s' >> .env && docker compose --profile %s up -d",
		base, strings.ReplaceAll(env, "\n", `\n`), kind,
	)
	return enrollment{Token: token, Env: env, Command: cmd}
}

// createDaemon attaches a new daemon to a node and returns its enrollment details.
func (s *Server) createDaemon(w http.ResponseWriter, r *http.Request) {
	nodeID, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	var req daemonRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if core.Get(req.Kind) == nil {
		invalid(w, "kind", "unknown core "+strconv.Quote(req.Kind))
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = req.Kind
	}

	token, err := randomToken(32)
	if err != nil {
		internalError(w, err)
		return
	}
	d, err := s.Queries.CreateDaemon(r.Context(), db.CreateDaemonParams{NodeID: nodeID, Kind: req.Kind, Name: name, TokenHash: hub.HashToken(token)})
	if err != nil {
		dbError(w, err)
		return
	}
	s.audit(r, "daemon.create", d.Name, map[string]any{"kind": d.Kind})
	created(w, map[string]any{"daemon": s.newDaemonResponse(d), "enrollment": s.newEnrollment(r, d.Kind, token)})
}

// updateDaemon edits a daemon's settings.
func (s *Server) updateDaemon(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	var req daemonRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if len(req.RawPatch) > 0 && string(req.RawPatch) != "null" {
		var probe map[string]any
		if err := json.Unmarshal(req.RawPatch, &probe); err != nil {
			invalid(w, "raw_patch", "raw patch must be a json object")
			return
		}
	} else {
		req.RawPatch = nil
	}

	cur, err := s.Queries.GetDaemon(r.Context(), id)
	if err != nil {
		dbError(w, err)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = cur.Name
	}
	enabled := cur.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	dnsServers := req.DNSServers
	if dnsServers == nil {
		dnsServers = cur.DnsServers
	}
	final := req.FinalOutbound
	if final == "" {
		final = cur.FinalOutbound
	}
	edgeListen, edgeDefault := cur.EdgeListen, cur.EdgeDefault
	if req.EdgeListen != nil {
		edgeListen = req.EdgeListen
	}
	if req.EdgeDefault != nil {
		edgeDefault = strings.TrimSpace(*req.EdgeDefault)
	}
	for _, l := range edgeListen {
		if _, _, err := net.SplitHostPort(l); err != nil {
			invalid(w, "edge_listen", fmt.Sprintf("listen address %q must look like :443", l))
			return
		}
	}
	if edgeDefault != "" {
		if _, _, err := net.SplitHostPort(edgeDefault); err != nil {
			invalid(w, "edge_default", fmt.Sprintf("%q must look like host:port", edgeDefault))
			return
		}
	}
	if req.LogLevel != "" && !slices.Contains([]string{"debug", "info", "warning", "error", "none"}, req.LogLevel) {
		invalid(w, "log_level", "log level must be debug, info, warning, error or none")
		return
	}
	if req.DNSStrategy != "" && !slices.Contains([]string{"prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"}, req.DNSStrategy) {
		invalid(w, "dns_strategy", "unknown DNS strategy")
		return
	}
	if final != "direct" && final != "block" {
		outs, err := s.Queries.ListOutbounds(r.Context())
		if err != nil {
			internalError(w, err)
			return
		}
		if !slices.ContainsFunc(outs, func(o db.Outbound) bool { return o.DaemonID == id && o.Tag == final }) {
			invalid(w, "final_outbound", fmt.Sprintf("this daemon has no outbound called %q", final))
			return
		}
	}

	d, err := s.Queries.UpdateDaemon(r.Context(), db.UpdateDaemonParams{
		ID: id, Name: name, Enabled: enabled, LogLevel: orDefault(req.LogLevel, cur.LogLevel), DnsServers: dnsServers,
		DnsStrategy: orDefault(req.DNSStrategy, cur.DnsStrategy), FinalOutbound: final, RawPatch: req.RawPatch,
		EdgeListen: edgeListen, EdgeDefault: edgeDefault,
	})
	if err != nil {
		dbError(w, err)
		return
	}
	if !enabled {
		s.Hub.Kick(id)
	}
	s.Hub.MarkDirty()
	s.audit(r, "daemon.update", d.Name, nil)
	ok(w, s.newDaemonResponse(d))
}

// orDefault returns v unless it is empty.
func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// deleteDaemon removes a daemon and its inbounds.
func (s *Server) deleteDaemon(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	rows, err := s.Queries.DeleteDaemon(r.Context(), id)
	if err != nil {
		dbError(w, err)
		return
	}
	if rows == 0 {
		notFound(w, "not found")
		return
	}
	s.Hub.Kick(id)
	s.Hub.MarkDirty()
	s.audit(r, "daemon.delete", strconv.FormatInt(id, 10), nil)
	noContent(w)
}

// rotateDaemon issues a new token, which cuts the old one off.
func (s *Server) rotateDaemon(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	d, err := s.Queries.GetDaemon(r.Context(), id)
	if err != nil {
		dbError(w, err)
		return
	}
	token, err := randomToken(32)
	if err != nil {
		internalError(w, err)
		return
	}
	if err := s.Queries.RotateDaemonToken(r.Context(), db.RotateDaemonTokenParams{ID: id, TokenHash: hub.HashToken(token)}); err != nil {
		internalError(w, err)
		return
	}
	s.Hub.Kick(id)
	s.audit(r, "daemon.rotate", d.Name, nil)
	ok(w, s.newEnrollment(r, d.Kind, token))
}

// restartDaemon restarts the core on a node.
func (s *Server) restartDaemon(w http.ResponseWriter, r *http.Request) {
	s.runCommand(w, r, link.CmdRestart, nil, "daemon.restart")
}

// daemonLogs returns the tail of a core's log.
func (s *Server) daemonLogs(w http.ResponseWriter, r *http.Request) {
	lines := r.URL.Query().Get("lines")
	if lines == "" {
		lines = "200"
	}
	s.runCommand(w, r, link.CmdLogs, map[string]string{"lines": lines}, "")
}

// runCommand sends a command to a daemon and relays the answer.
func (s *Server) runCommand(w http.ResponseWriter, r *http.Request, name string, args map[string]string, auditAction string) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	res, err := s.Hub.Command(r.Context(), id, name, args)
	switch err {
	case nil:
	case hub.ErrOffline:
		conflict(w, "the daemon is offline")
		return
	default:
		fail(w, http.StatusGatewayTimeout, "timeout", err.Error())
		return
	}
	if auditAction != "" {
		s.audit(r, auditAction, r.PathValue("id"), nil)
	}
	ok(w, res)
}

// previewDaemon renders the native config a daemon would run right now.
func (s *Server) previewDaemon(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	raw, err := s.Hub.Preview(r.Context(), id)
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

// listCores lists the cores this panel knows how to drive.
func (s *Server) listCores(w http.ResponseWriter, r *http.Request) {
	ok(w, core.GetAll())
}

// registerNodeFiles serves the compose file new nodes download.
func registerNodeFiles(mux *http.ServeMux) {
	mux.HandleFunc("GET /node/docker-compose.yml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		_, _ = w.Write(node.Compose)
	})
}
