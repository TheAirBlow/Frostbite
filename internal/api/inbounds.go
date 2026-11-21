package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"frostbite/internal/compose"
	"frostbite/internal/core"
	"frostbite/internal/db"
	"frostbite/internal/share"
	"frostbite/internal/spec"
)

// registerInbounds registers inbound and host endpoints.
func (s *Server) registerInbounds(mux authMux) {
	mux.Node("GET /inbounds", nil, s.listInbounds)
	mux.Node("POST /inbounds", newInbound, s.createInbound)
	mux.Node("PUT /inbounds/{id}", inboundAtPath, s.updateInbound)
	mux.Node("DELETE /inbounds/{id}", inboundAtPath, s.deleteInbound)
	mux.Node("POST /hosts", newHost, s.createHost)
	mux.Node("PUT /hosts/{id}", hostAtPath, s.updateHost)
	mux.Node("DELETE /hosts/{id}", hostAtPath, s.deleteHost)
	mux.Node("GET /presets", nil, s.listPresets)
	mux.Auth("GET /schema", s.schema)
}

// inboundResponse is an inbound with the hosts that advertise it.
type inboundResponse struct {
	db.Inbound
	Hosts []db.Host `json:"hosts"`
}

// listInbounds lists every inbound with its hosts.
func (s *Server) listInbounds(w http.ResponseWriter, r *http.Request) {
	inbounds, err := s.Queries.ListInbounds(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	hosts, err := s.Queries.ListHosts(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	mine, err := s.daemonFilter(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	byInbound := map[int64][]db.Host{}
	for _, h := range hosts {
		byInbound[h.InboundID] = append(byInbound[h.InboundID], h)
	}
	out := make([]inboundResponse, 0, len(inbounds))
	for _, in := range inbounds {
		if mine(in.DaemonID) {
			out = append(out, inboundResponse{Inbound: in, Hosts: orEmpty(byInbound[in.ID])})
		}
	}
	ok(w, out)
}

// inboundRequest is the JSON body for creating or editing an inbound.
type inboundRequest struct {
	DaemonID  int64           `json:"daemon_id"`
	Tag       string          `json:"tag"`
	Remark    string          `json:"remark"`
	Protocol  string          `json:"protocol"`
	Listen    string          `json:"listen"`
	Port      int32           `json:"port"`
	Transport spec.Transport  `json:"transport"`
	Security  spec.Security   `json:"security"`
	Options   spec.Options    `json:"options"`
	Sniffing  spec.Sniffing   `json:"sniffing"`
	Forward   *spec.Forward   `json:"forward"`
	RawPatch  json.RawMessage `json:"raw_patch"`
	Enabled   *bool           `json:"enabled"`
	Sort      int32           `json:"sort"`
	EdgeID    *int64          `json:"edge_daemon_id"`
	EdgeSNI   []string        `json:"edge_sni"`
	Preset    string          `json:"preset"`
	Params    map[string]any  `json:"params"`
}

// specInbound converts a request into the spec form for validation.
func (req inboundRequest) specInbound() spec.Inbound {
	return spec.Inbound{
		Tag: req.Tag, Protocol: req.Protocol, Listen: req.Listen, Port: int(req.Port), Transport: req.Transport,
		Security: req.Security, Options: req.Options, Sniffing: req.Sniffing, Forward: req.Forward,
	}
}

// normalize puts what was typed into the one shape that gets stored.
func (req *inboundRequest) normalize() {
	req.Tag = strings.TrimSpace(req.Tag)
	if req.Protocol == spec.ProtoTurnable {
		req.Options = req.Options.MigrateTurnable()
	}
}

// resolveTurnable points the destinations that lead to one of the panel's inbounds at that inbound, and refuses the
// ones the tunnel could not reach.
func (s *Server) resolveTurnable(ctx context.Context, req *inboundRequest) (verr, err error) {
	if req.Protocol != spec.ProtoTurnable || len(req.Options.TRoutes) == 0 {
		return nil, nil
	}
	d, derr := s.Queries.GetDaemon(ctx, req.DaemonID)
	if derr != nil {
		return nil, nil // check reports a daemon that is not there
	}
	routes := slices.Clone(req.Options.TRoutes)
	for i, r := range routes {
		if r.Kind != spec.RouteInbound || r.InboundID <= 0 {
			continue
		}
		at := fmt.Sprintf("options.t_routes.%d.inbound_id", i)
		target, gerr := s.Queries.GetInbound(ctx, r.InboundID)
		if errors.Is(gerr, pgx.ErrNoRows) {
			return spec.Invalid(at, "that inbound does not exist"), nil
		}
		if gerr != nil {
			return nil, gerr
		}
		switch {
		case target.Protocol == spec.ProtoForward || target.Protocol == spec.ProtoTurnable || target.Protocol == spec.ProtoShadowTLS:
			return spec.Invalid(at, "a tunnel can't lead to a %s inbound", target.Protocol), nil
		case target.EdgeDaemonID != nil:
			return spec.Invalid(at, "that inbound sits behind an edge daemon and expects its PROXY header, pick one with its own port"), nil
		}
		td, gerr := s.Queries.GetDaemon(ctx, target.DaemonID)
		if gerr != nil {
			return nil, gerr
		}
		if td.NodeID != d.NodeID {
			return spec.Invalid(at, "that inbound runs on another server, and the tunnel only reaches this one"), nil
		}
		routes[i].Target = compose.LoopbackTarget(target)
	}
	req.Options.TRoutes = routes
	return nil, nil
}

// check validates an inbound against its daemon's core and the other inbounds on that daemon.
func (s *Server) check(ctx context.Context, req inboundRequest, selfID int64) (verr, err error) {
	d, err := s.Queries.GetDaemon(ctx, req.DaemonID)
	if err != nil {
		return spec.Invalid("daemon_id", "the daemon does not exist"), nil
	}
	desc := core.Get(d.Kind)
	if desc == nil {
		return spec.Invalid("daemon_id", "unknown core %s", d.Kind), nil
	}
	if strings.TrimSpace(req.Tag) == "" {
		return spec.Invalid("tag", "tag is required"), nil
	}
	if d.Kind == "edge" {
		return spec.Invalid("daemon_id", "an edge daemon shares ports, it does not run inbounds of its own"), nil
	}
	if verr, err := s.checkEdge(ctx, req, d); err != nil || verr != nil {
		return verr, err
	}

	if len(req.RawPatch) > 0 && string(req.RawPatch) != "null" {
		var probe map[string]any
		if err := json.Unmarshal(req.RawPatch, &probe); err != nil {
			return spec.Invalid("raw_patch", "raw patch must be a json object"), nil
		}
	}

	others, err := s.Queries.ListInboundsByDaemon(ctx, req.DaemonID)
	if err != nil {
		return nil, err
	}
	all := spec.Daemon{Kind: d.Kind, Inbounds: []spec.Inbound{req.specInbound()}}
	for _, o := range others {
		if o.ID == selfID || !o.Enabled {
			continue
		}
		all.Inbounds = append(all.Inbounds, spec.Inbound{
			Tag: o.Tag, Protocol: o.Protocol, Listen: o.Listen, Port: int(o.Port), Transport: o.Transport,
			Security: o.Security, Options: o.Options, Forward: o.Forward,
		})
	}
	if err := desc.Caps.Check(all); err != nil {
		return err, nil
	}
	if err := all.Validate(); err != nil {
		return err, nil
	}
	return nil, nil
}

// createInbound adds an inbound, either from a full definition or from a preset.
func (s *Server) createInbound(w http.ResponseWriter, r *http.Request) {
	var req inboundRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}

	if req.Preset != "" {
		if err := s.applyPreset(r.Context(), &req); err != nil {
			badInput(w, err)
			return
		}
	}
	req.normalize()
	if verr, err := s.resolveTurnable(r.Context(), &req); err != nil {
		internalError(w, err)
		return
	} else if verr != nil {
		badInput(w, verr)
		return
	}
	if verr, err := s.check(r.Context(), req, 0); err != nil {
		internalError(w, err)
		return
	} else if verr != nil {
		badInput(w, verr)
		return
	}

	in, err := s.insertInbound(r.Context(), req)
	if err != nil {
		dbError(w, err)
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "inbound.create", in.Tag, map[string]any{"protocol": in.Protocol, "port": in.Port})
	created(w, inboundResponse{Inbound: in, Hosts: s.defaultHosts(r.Context(), in)})
}

// insertInbound stores an inbound.
func (s *Server) insertInbound(ctx context.Context, req inboundRequest) (db.Inbound, error) {
	return s.Queries.CreateInbound(ctx, db.CreateInboundParams{
		DaemonID: req.DaemonID, Tag: strings.TrimSpace(req.Tag), Remark: req.Remark, Protocol: req.Protocol, Listen: req.Listen,
		Port: req.Port, Transport: req.Transport, Security: req.Security, Options: req.Options, Sniffing: req.Sniffing,
		Forward: req.Forward, RawPatch: nilIfEmpty(req.RawPatch), Enabled: req.Enabled == nil || *req.Enabled, System: req.Protocol == spec.ProtoForward,
		Sort: req.Sort, EdgeDaemonID: req.EdgeID, EdgeSni: orEmpty(req.EdgeSNI),
	})
}

// defaultHosts gives a fresh inbound a host so it shows up in subscriptions straight away.
func (s *Server) defaultHosts(ctx context.Context, in db.Inbound) []db.Host {
	if in.Protocol == spec.ProtoForward {
		return []db.Host{}
	}
	h, err := s.Queries.CreateHost(ctx, db.CreateHostParams{
		InboundID: in.ID, Remark: share.DefaultRemark, Alpn: []string{}, Enabled: true,
	})
	if err != nil {
		return []db.Host{}
	}
	return []db.Host{h}
}

// nilIfEmpty turns an empty patch into SQL NULL.
func nilIfEmpty(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return raw
}

// updateInbound edits an inbound.
func (s *Server) updateInbound(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	cur, err := s.Queries.GetInbound(r.Context(), id)
	if err != nil {
		dbError(w, err)
		return
	}
	var req inboundRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	req.DaemonID = cur.DaemonID

	req.normalize()
	if verr, err := s.resolveTurnable(r.Context(), &req); err != nil {
		internalError(w, err)
		return
	} else if verr != nil {
		badInput(w, verr)
		return
	}
	if verr, err := s.check(r.Context(), req, id); err != nil {
		internalError(w, err)
		return
	} else if verr != nil {
		badInput(w, verr)
		return
	}

	in, err := s.Queries.UpdateInbound(r.Context(), db.UpdateInboundParams{
		ID: id, Tag: strings.TrimSpace(req.Tag), Remark: req.Remark, Protocol: req.Protocol, Listen: req.Listen, Port: req.Port,
		Transport: req.Transport, Security: req.Security, Options: req.Options, Sniffing: req.Sniffing, Forward: req.Forward,
		RawPatch: nilIfEmpty(req.RawPatch), Enabled: req.Enabled == nil || *req.Enabled, Sort: req.Sort,
		EdgeDaemonID: req.EdgeID, EdgeSni: orEmpty(req.EdgeSNI),
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
	s.audit(r, "inbound.update", in.Tag, nil)
	ok(w, in)
}

// deleteInbound removes an inbound, along with any bridge that pointed at it.
func (s *Server) deleteInbound(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	if err := s.removeBridgesTo(r.Context(), id); err != nil {
		internalError(w, err)
		return
	}
	rows, err := s.Queries.DeleteInbound(r.Context(), id)
	if err != nil {
		dbError(w, err)
		return
	}
	if rows == 0 {
		notFound(w, "not found")
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "inbound.delete", r.PathValue("id"), nil)
	noContent(w)
}

// hostRequest is the JSON body for creating or editing a host.
type hostRequest struct {
	InboundID   int64      `json:"inbound_id"`
	Remark      string     `json:"remark"`
	Address     string     `json:"address"`
	Port        *int32     `json:"port"`
	SNI         string     `json:"sni"`
	Host        string     `json:"host"`
	Path        string     `json:"path"`
	ALPN        []string   `json:"alpn"`
	Fingerprint string     `json:"fingerprint"`
	Insecure    bool       `json:"insecure"`
	Mux         *spec.Mux  `json:"mux"`
	Fragment    *spec.Frag `json:"fragment"`
	Enabled     *bool      `json:"enabled"`
	Sort        int32      `json:"sort"`
}

// clean validates a host request.
func (h *hostRequest) clean() error {
	h.Address = strings.TrimSpace(h.Address)
	if h.Port != nil && (*h.Port < 1 || *h.Port > 65535) {
		return spec.Invalid("port", "port must be between 1 and 65535")
	}
	if h.Remark == "" {
		h.Remark = share.DefaultRemark
	}
	if err := spec.CheckPlaceholders(h.Remark, spec.RemarkPlaceholders); err != nil {
		return spec.Invalid("remark", "%s", err)
	}
	if f := h.Fragment; f != nil && f.Enabled {
		for field, v := range map[string]string{"fragment.length": f.Length, "fragment.interval": f.Interval} {
			if v != "" && !rangeText.MatchString(v) {
				return spec.Invalid(field, "use a number or a range like 10-20")
			}
		}
	}
	if m := h.Mux; m != nil && m.Concurrency < 0 {
		return spec.Invalid("mux.concurrency", "concurrency cannot be negative")
	}
	return nil
}

var rangeText = regexp.MustCompile(`^\d+(-\d+)?$`)

// createHost adds a host to an inbound.
func (s *Server) createHost(w http.ResponseWriter, r *http.Request) {
	var req hostRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if err := req.clean(); err != nil {
		badInput(w, err)
		return
	}
	h, err := s.Queries.CreateHost(r.Context(), db.CreateHostParams{
		InboundID: req.InboundID, Remark: req.Remark, Address: req.Address, Port: req.Port, Sni: req.SNI, Host: req.Host,
		Path: req.Path, Alpn: orEmpty(req.ALPN), Fingerprint: req.Fingerprint, Insecure: req.Insecure, Mux: req.Mux,
		Fragment: req.Fragment, Enabled: req.Enabled == nil || *req.Enabled, Sort: req.Sort,
	})
	if err != nil {
		dbError(w, err)
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "host.create", h.Remark, nil)
	created(w, h)
}

// updateHost edits a host.
func (s *Server) updateHost(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	var req hostRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if err := req.clean(); err != nil {
		badInput(w, err)
		return
	}
	h, err := s.Queries.UpdateHost(r.Context(), db.UpdateHostParams{
		ID: id, Remark: req.Remark, Address: req.Address, Port: req.Port, Sni: req.SNI, Host: req.Host, Path: req.Path,
		Alpn: orEmpty(req.ALPN), Fingerprint: req.Fingerprint, Insecure: req.Insecure, Mux: req.Mux, Fragment: req.Fragment,
		Enabled: req.Enabled == nil || *req.Enabled, Sort: req.Sort,
	})
	if err != nil {
		dbError(w, err)
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "host.update", h.Remark, nil)
	ok(w, h)
}

// deleteHost removes a host.
func (s *Server) deleteHost(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	rows, err := s.Queries.DeleteHost(r.Context(), id)
	if err != nil {
		dbError(w, err)
		return
	}
	if rows == 0 {
		notFound(w, "not found")
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "host.delete", r.PathValue("id"), nil)
	noContent(w)
}

// schema returns the form definitions the frontend builds inbound editors from.
func (s *Server) schema(w http.ResponseWriter, r *http.Request) {
	ok(w, spec.Schema())
}

// errNoPreset is returned for an unknown preset id.
func errNoPreset(id string) error { return fmt.Errorf("unknown preset %q", id) }

// checkEdge validates putting an inbound behind an edge daemon.
func (s *Server) checkEdge(ctx context.Context, req inboundRequest, d db.Daemon) (verr, err error) {
	if req.EdgeID == nil {
		return nil, nil
	}
	edge, err := s.Queries.GetDaemon(ctx, *req.EdgeID)
	if err != nil || edge.Kind != "edge" {
		return spec.Invalid("edge_daemon_id", "pick an edge daemon to put this inbound behind"), nil
	}
	if edge.NodeID != d.NodeID {
		return spec.Invalid("edge_daemon_id", "the edge daemon has to run on the same node as the inbound"), nil
	}
	if req.specInbound().Network() != "tcp" {
		return spec.Invalid("edge_daemon_id", "the edge shares TCP ports, this inbound uses UDP"), nil
	}
	if req.Security.Type != spec.SecurityTLS && req.Security.Type != spec.SecurityReality {
		return spec.Invalid("edge_daemon_id", "the edge picks inbounds by their TLS server name, so this one needs tls or reality"), nil
	}
	if req.Protocol == spec.ProtoForward {
		return spec.Invalid("edge_daemon_id", "relays cannot sit behind an edge"), nil
	}
	return nil, nil
}
