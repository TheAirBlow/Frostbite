package api

import (
	"net/http"
	"slices"
	"strings"

	"frostbite/internal/core"
	"frostbite/internal/db"
	"frostbite/internal/share"
	"frostbite/internal/spec"
	"net/netip"
	"regexp"
)

// registerRouting registers outbound and routing rule endpoints.
func (s *Server) registerRouting(mux authMux) {
	mux.Admin("GET /outbounds", s.listOutbounds)
	mux.Admin("POST /outbounds", s.createOutbound)
	mux.Admin("PUT /outbounds/{id}", s.updateOutbound)
	mux.Admin("DELETE /outbounds/{id}", s.deleteOutbound)
	mux.Admin("GET /rules", s.listRules)
	mux.Admin("POST /rules", s.createRule)
	mux.Admin("POST /rules/reorder", s.reorderRules)
	mux.Admin("PUT /rules/{id}", s.updateRule)
	mux.Admin("DELETE /rules/{id}", s.deleteRule)
	mux.Admin("GET /rules/presets", s.ruleTemplates)
}

// listOutbounds lists user defined outbounds. direct and block always exist implicitly.
func (s *Server) listOutbounds(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Queries.ListOutbounds(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	ok(w, orEmpty(rows))
}

// outboundRequest is the JSON body for creating or editing an outbound.
type outboundRequest struct {
	DaemonID        int64          `json:"daemon_id"`
	Tag             string         `json:"tag"`
	Kind            string         `json:"kind"`
	Upstream        *spec.Upstream `json:"upstream"`
	Link            string         `json:"link"` // a share link, parsed into the upstream
	TargetInboundID *int64         `json:"target_inbound_id"`
	Interface       string         `json:"interface"`
	Strategy        string         `json:"strategy"`
	Sort            int32          `json:"sort"`
}

// clean validates an outbound request against its daemon's core.
func (s *Server) cleanOutbound(r *http.Request, req *outboundRequest) error {
	req.Tag = strings.TrimSpace(req.Tag)
	if req.Tag == "" {
		return spec.Invalid("tag", "tag is required")
	}
	if req.Tag == "direct" || req.Tag == "block" {
		return spec.Invalid("tag", `"direct" and "block" are built in, pick another tag`)
	}
	d, err := s.Queries.GetDaemon(r.Context(), req.DaemonID)
	if err != nil {
		return spec.Invalid("daemon_id", "the daemon does not exist")
	}
	desc := core.Get(d.Kind)
	if desc == nil || !slices.Contains(desc.Caps.Outbounds, req.Kind) {
		return spec.Invalid("daemon_id", "this core can't run a %s outbound", req.Kind)
	}

	if req.Link != "" {
		up, err := share.ParseLink(req.Link)
		if err != nil {
			return spec.Invalid("link", "%s", err)
		}
		req.Upstream = &up
		req.Kind = spec.OutProxy
	}
	if req.Kind == spec.OutWarp && req.Interface == "" {
		if acc, err := s.loadWarp(r.Context()); err != nil || acc == nil {
			return spec.Invalid("interface", "register a WARP account first, or name a network interface to use instead")
		}
	}
	switch req.Kind {
	case spec.OutProxy:
		if req.TargetInboundID == nil && (req.Upstream == nil || req.Upstream.Address == "") {
			if req.Upstream != nil {
				return spec.Invalid("upstream.address", "the address is required")
			}
			return spec.Invalid("target_inbound_id", "a proxy outbound needs a target inbound, a share link or an upstream")
		}
		if u := req.Upstream; u != nil && req.TargetInboundID == nil && (u.Port < 1 || u.Port > 65535) {
			return spec.Invalid("upstream.port", "port must be between 1 and 65535")
		}
		if req.TargetInboundID != nil {
			req.Upstream = nil
		}
	default:
		req.Upstream, req.TargetInboundID = nil, nil
	}
	return nil
}

// createOutbound adds an outbound to a daemon.
func (s *Server) createOutbound(w http.ResponseWriter, r *http.Request) {
	var req outboundRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if err := s.cleanOutbound(r, &req); err != nil {
		badInput(w, err)
		return
	}
	o, err := s.Queries.CreateOutbound(r.Context(), db.CreateOutboundParams{
		DaemonID: req.DaemonID, Tag: req.Tag, Kind: req.Kind, Upstream: req.Upstream, TargetInboundID: req.TargetInboundID,
		Interface: req.Interface, Strategy: req.Strategy, Sort: req.Sort,
	})
	if err != nil {
		dbError(w, err)
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "outbound.create", o.Tag, nil)
	created(w, o)
}

// updateOutbound edits an outbound.
func (s *Server) updateOutbound(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	cur, err := s.Queries.GetOutbound(r.Context(), id)
	if err != nil {
		dbError(w, err)
		return
	}
	var req outboundRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	req.DaemonID = cur.DaemonID
	if err := s.cleanOutbound(r, &req); err != nil {
		badInput(w, err)
		return
	}
	o, err := s.Queries.UpdateOutbound(r.Context(), db.UpdateOutboundParams{
		ID: id, Tag: req.Tag, Kind: req.Kind, Upstream: req.Upstream, TargetInboundID: req.TargetInboundID,
		Interface: req.Interface, Strategy: req.Strategy, Sort: req.Sort,
	})
	if err != nil {
		dbError(w, err)
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "outbound.update", o.Tag, nil)
	ok(w, o)
}

// deleteOutbound removes an outbound.
func (s *Server) deleteOutbound(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	rows, err := s.Queries.DeleteOutbound(r.Context(), id)
	if err != nil {
		dbError(w, err)
		return
	}
	if rows == 0 {
		notFound(w, "not found")
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "outbound.delete", r.PathValue("id"), nil)
	noContent(w)
}

// listRules lists routing rules in priority order.
func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Queries.ListRules(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	ok(w, orEmpty(rows))
}

// ruleRequest is the JSON body for creating or editing a rule.
type ruleRequest struct {
	DaemonID *int64    `json:"daemon_id"` // empty means every daemon that has the outbound
	Name     string    `json:"name"`
	Match    spec.Rule `json:"match"`
	Outbound string    `json:"outbound"`
	Enabled  *bool     `json:"enabled"`
	Sort     int32     `json:"sort"`
}

// cleanRule checks a rule matches on something and goes somewhere.
func cleanRule(req *ruleRequest) error {
	req.Outbound = strings.TrimSpace(req.Outbound)
	if req.Outbound == "" {
		return spec.Invalid("outbound", "pick an outbound for the rule")
	}
	m := req.Match
	if len(m.InboundTags)+len(m.Users)+len(m.Domain)+len(m.DomainSuffix)+len(m.DomainKw)+len(m.GeoSite)+len(m.GeoIP)+
		len(m.IPCIDR)+len(m.Port)+len(m.Protocol) == 0 && m.Network == "" {
		return spec.Invalid("match", "a rule needs at least one condition")
	}
	for i, c := range m.IPCIDR {
		if _, err := netip.ParsePrefix(c); err != nil {
			if _, err := netip.ParseAddr(c); err != nil {
				return spec.Invalid("match.ip_cidr", "%q is not an IP range like 10.0.0.0/8 (entry %d)", c, i+1)
			}
		}
	}
	for _, p := range m.Port {
		if !portSpec.MatchString(p) {
			return spec.Invalid("match.port", "%q is not a port like 443 or a range like 6881-6889", p)
		}
	}
	for _, c := range m.GeoIP {
		if len(c) != 2 {
			return spec.Invalid("match.geoip", "%q is not a two letter country code", c)
		}
	}
	req.Match.Outbound = ""
	return nil
}

var portSpec = regexp.MustCompile(`^\d{1,5}(-\d{1,5})?$`)

// createRule adds a routing rule.
func (s *Server) createRule(w http.ResponseWriter, r *http.Request) {
	var req ruleRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if err := cleanRule(&req); err != nil {
		badInput(w, err)
		return
	}
	rule, err := s.Queries.CreateRule(r.Context(), db.CreateRuleParams{
		DaemonID: req.DaemonID, Name: req.Name, Match: req.Match, Outbound: req.Outbound, Enabled: req.Enabled == nil || *req.Enabled, Sort: req.Sort,
	})
	if err != nil {
		dbError(w, err)
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "rule.create", rule.Name, nil)
	created(w, rule)
}

// updateRule edits a routing rule.
func (s *Server) updateRule(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	var req ruleRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if err := cleanRule(&req); err != nil {
		badInput(w, err)
		return
	}
	rule, err := s.Queries.UpdateRule(r.Context(), db.UpdateRuleParams{
		ID: id, DaemonID: req.DaemonID, Name: req.Name, Match: req.Match, Outbound: req.Outbound, Enabled: req.Enabled == nil || *req.Enabled, Sort: req.Sort,
	})
	if err != nil {
		dbError(w, err)
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "rule.update", rule.Name, nil)
	ok(w, rule)
}

// deleteRule removes a rule.
func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	rows, err := s.Queries.DeleteRule(r.Context(), id)
	if err != nil {
		dbError(w, err)
		return
	}
	if rows == 0 {
		notFound(w, "not found")
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "rule.delete", r.PathValue("id"), nil)
	noContent(w)
}

// reorderRules rewrites rule priorities to match the order of the ids given.
func (s *Server) reorderRules(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	for i, id := range req.IDs {
		rule, err := s.Queries.GetRule(r.Context(), id)
		if err != nil {
			dbError(w, err)
			return
		}
		if _, err := s.Queries.UpdateRule(r.Context(), db.UpdateRuleParams{
			ID: id, DaemonID: rule.DaemonID, Name: rule.Name, Match: rule.Match, Outbound: rule.Outbound, Enabled: rule.Enabled, Sort: int32(i),
		}); err != nil {
			internalError(w, err)
			return
		}
	}
	s.Hub.MarkDirty()
	noContent(w)
}

// ruleTemplate is a ready made rule the UI can offer.
type ruleTemplate struct {
	ID          string    `json:"id"`
	Label       string    `json:"label"`
	Description string    `json:"description"`
	Match       spec.Rule `json:"match"`
	Outbound    string    `json:"outbound"` // empty means the user picks one
}

// ruleTemplates lists common rules.
func (s *Server) ruleTemplates(w http.ResponseWriter, r *http.Request) {
	ok(w, []ruleTemplate{
		{ID: "ads", Label: "Block ads", Description: "Drops known ad and tracker domains.", Match: spec.Rule{GeoSite: []string{"category-ads-all"}}, Outbound: "block"},
		{ID: "bittorrent", Label: "Block BitTorrent", Description: "Needs sniffing on the inbound.", Match: spec.Rule{Protocol: []string{"bittorrent"}}, Outbound: "block"},
		{ID: "private", Label: "Block private networks", Description: "Stops users from reaching the node's LAN.", Match: spec.Rule{IPCIDR: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7"}}, Outbound: "block"},
		{ID: "cn-sites", Label: "China sites direct", Match: spec.Rule{GeoSite: []string{"cn"}}, Outbound: "direct"},
		{ID: "cn-ip", Label: "China IPs direct", Match: spec.Rule{GeoIP: []string{"cn"}}, Outbound: "direct"},
		{ID: "ir-sites", Label: "Iran sites direct", Match: spec.Rule{GeoSite: []string{"category-ir"}}, Outbound: "direct"},
		{ID: "ir-ip", Label: "Iran IPs direct", Match: spec.Rule{GeoIP: []string{"ir"}}, Outbound: "direct"},
		{ID: "ru-ip", Label: "Russia IPs direct", Match: spec.Rule{GeoIP: []string{"ru"}}, Outbound: "direct"},
		{ID: "streaming", Label: "Streaming through an outbound", Description: "Netflix, Disney+, Spotify and friends.", Match: spec.Rule{GeoSite: []string{"netflix", "disney", "spotify"}}},
		{ID: "ai", Label: "AI services through an outbound", Description: "OpenAI, Anthropic and similar.", Match: spec.Rule{GeoSite: []string{"openai", "anthropic"}}},
		{ID: "quic", Label: "Block QUIC", Description: "Forces browsers back to TCP, which proxies handle better.", Match: spec.Rule{Network: "udp", Port: []string{"443"}}, Outbound: "block"},
	})
}
