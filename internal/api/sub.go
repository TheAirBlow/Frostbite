package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"frostbite/internal/compose"
	"frostbite/internal/db"
	"frostbite/internal/metrics"
	"frostbite/internal/share"
	"frostbite/internal/spec"
)

// topoTTL is how long a loaded topology is reused between subscription fetches.
const topoTTL = 3 * time.Second

// topoCache keeps the topology around so a burst of client refreshes costs one load.
type topoCache struct {
	mu sync.Mutex
	at time.Time
	t  *compose.Topology
}

// topology returns a recent topology.
func (s *Server) loadTopology(ctx context.Context) (*compose.Topology, error) {
	s.topo.mu.Lock()
	defer s.topo.mu.Unlock()
	if s.topo.t != nil && time.Since(s.topo.at) < topoTTL {
		return s.topo.t, nil
	}
	t, err := compose.LoadTopology(ctx, s.Queries)
	if err != nil {
		return nil, err
	}
	s.topo.t, s.topo.at = t, time.Now()
	return t, nil
}

// profilesOf lists the connections a user may use right now.
func (s *Server) profilesOf(ctx context.Context, u db.User) ([]compose.Profile, error) {
	t, err := s.loadTopology(ctx)
	if err != nil {
		return nil, err
	}
	squads, err := s.Queries.ListUserSquadIDs(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	return t.Profiles(u, squads), nil
}

// registerSub registers subscription management endpoints.
func (s *Server) registerSub(mux authMux) {
	mux.Admin("GET /sub/templates", s.listTemplates)
	mux.Admin("POST /sub/templates", s.createTemplate)
	mux.Admin("PUT /sub/templates/{id}", s.updateTemplate)
	mux.Admin("DELETE /sub/templates/{id}", s.deleteTemplate)
	mux.Admin("GET /sub/rules", s.listSubRules)
	mux.Admin("POST /sub/rules", s.createSubRule)
	mux.Admin("PUT /sub/rules/{id}", s.updateSubRule)
	mux.Admin("DELETE /sub/rules/{id}", s.deleteSubRule)
	mux.Admin("GET /sub/preview", s.previewSub)
	mux.Auth("GET /sub/formats", s.subFormats)
	mux.HandleFunc("GET /portal/{token}", s.portal)
}

// registerPublicSub registers the subscription link that clients fetch, which lives outside /api.
func (s *Server) registerPublicSub(mux *http.ServeMux) {
	mux.HandleFunc("GET /sub/{token}", s.serveSub)
	mux.HandleFunc("GET /sub/{token}/{format}", s.serveSub)
}

// subFormats lists the formats the panel can serve.
func (s *Server) subFormats(w http.ResponseWriter, r *http.Request) {
	ok(w, share.Formats)
}

// subDoc is a rendered subscription with the headers that go with it.
type subDoc struct {
	Body        []byte
	ContentType string
	Format      string
	Headers     map[string]string
}

// build renders the subscription for a user as a client with the given user agent and device would see it.
func (s *Server) buildSub(ctx context.Context, u db.User, ua, format string, dev deviceInfo) (subDoc, error) {
	set := defaultSub()
	if err := s.loadSetting(ctx, "subscription", &set); err != nil {
		return subDoc{}, err
	}

	var patch json.RawMessage
	if format == "" || format == "auto" {
		f, p, err := s.formatFor(ctx, ua, set)
		if err != nil {
			return subDoc{}, err
		}
		format, patch = f, p
	}

	profiles, notice, err := s.subProfiles(ctx, u, set, dev)
	if err != nil {
		return subDoc{}, err
	}
	if len(profiles) == 0 {
		return subDoc{}, fmt.Errorf("nothing to serve: this user has no active connections")
	}

	ups := make([]spec.Upstream, len(profiles))
	for i, p := range profiles {
		ups[i] = p.Upstream
	}
	body, err := share.Render(format, ups, patch)
	if err != nil {
		return subDoc{}, err
	}

	h := map[string]string{
		"Profile-Update-Interval": strconv.Itoa(set.UpdateHours),
		"Profile-Title":           "base64:" + base64.StdEncoding.EncodeToString([]byte(set.Title)),
		"Content-Disposition":     fmt.Sprintf(`attachment; filename="%s"`, url.PathEscape(u.Username)),
	}
	var expire int64
	if u.ExpireAt != nil {
		expire = u.ExpireAt.Unix()
	}
	h["Subscription-Userinfo"] = share.UserInfo(0, u.TrafficUsed, u.TrafficLimit, expire)
	if set.SupportURL != "" {
		h["Support-Url"] = set.SupportURL
	}
	if set.WebPageURL != "" {
		h["Profile-Web-Page-Url"] = set.WebPageURL
	}
	announce := set.Announce
	if notice != "" {
		announce = notice
	}
	if announce != "" {
		h["Announce"] = "base64:" + base64.StdEncoding.EncodeToString([]byte(announce))
	}
	return subDoc{Body: body, ContentType: share.ContentType(format), Format: format, Headers: h}, nil
}

// formatFor picks a format from the user agent rules, then the default, then built in detection.
func (s *Server) formatFor(ctx context.Context, ua string, set SubSettings) (string, json.RawMessage, error) {
	rules, err := s.Queries.ListSubRules(ctx)
	if err != nil {
		return "", nil, err
	}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		re, err := regexp.Compile("(?i)" + r.UaRegex)
		if err != nil || !re.MatchString(ua) {
			continue
		}
		var patch json.RawMessage
		if r.TemplateID != nil {
			if t, err := s.Queries.GetSubTemplate(ctx, *r.TemplateID); err == nil {
				patch = t.Patch
			}
		}
		return r.Format, patch, nil
	}
	if set.DefaultFormat != "" && set.DefaultFormat != "auto" {
		return set.DefaultFormat, nil, nil
	}
	return share.DetectFormat(ua), nil, nil
}

// deviceInfo is what a client tells us about the device it runs on.
type deviceInfo struct {
	HWID, Platform, Model, OS, UA string
}

// deviceOf reads the headers clients like Happ and Hiddify send.
func deviceOf(r *http.Request) deviceInfo {
	h := r.Header
	return deviceInfo{
		HWID: h.Get("X-Hwid"), Platform: h.Get("X-Device-Os"), Model: h.Get("X-Device-Model"), OS: h.Get("X-Ver-Os"), UA: r.UserAgent(),
	}
}

// subProfiles returns the connections to serve, or a single notice profile when the user can't connect.
func (s *Server) subProfiles(ctx context.Context, u db.User, set SubSettings, dev deviceInfo) ([]compose.Profile, string, error) {
	reason := ""
	switch u.Status {
	case "disabled":
		reason = "Account disabled"
	case "expired":
		reason = "Subscription expired"
	case "limited":
		reason = "Traffic limit reached"
	}
	if reason == "" && u.DeviceLimit > 0 {
		reason = s.deviceCheck(ctx, u, dev)
	}
	if reason != "" {
		if !set.NoticeProfiles {
			return nil, reason, nil
		}
		return []compose.Profile{noticeProfile(reason)}, reason, nil
	}

	profiles, err := s.profilesOf(ctx, u)
	if err != nil {
		return nil, "", err
	}
	if set.HideBridges {
		kept := profiles[:0]
		for _, p := range profiles {
			if !p.Bridge {
				kept = append(kept, p)
			}
		}
		profiles = kept
	}
	return profiles, "", nil
}

// deviceCheck registers the device and says why it must be refused, if it must.
func (s *Server) deviceCheck(ctx context.Context, u db.User, dev deviceInfo) string {
	reason := s.checkDevice(ctx, u, dev)
	switch reason {
	case "":
		metrics.Devices.WithLabelValues("allowed").Inc()
	case "Device limit reached":
		metrics.Devices.WithLabelValues("limit_reached").Inc()
	default:
		metrics.Devices.WithLabelValues("no_device_id").Inc()
	}
	return reason
}

// checkDevice does the work of deviceCheck.
func (s *Server) checkDevice(ctx context.Context, u db.User, dev deviceInfo) string {
	if dev.HWID == "" {
		return "This app does not send a device id"
	}
	if _, err := s.Queries.GetDevice(ctx, db.GetDeviceParams{UserID: u.ID, Hwid: dev.HWID}); err != nil {
		n, err := s.Queries.CountDevices(ctx, u.ID)
		if err != nil {
			return ""
		}
		if n >= int64(u.DeviceLimit) {
			return "Device limit reached"
		}
	}
	_ = s.Queries.UpsertDevice(ctx, db.UpsertDeviceParams{
		UserID: u.ID, Hwid: dev.HWID, Platform: dev.Platform, Model: dev.Model, OsVersion: dev.OS, UserAgent: dev.UA,
	})
	return ""
}

// noticeProfile is a connection that goes nowhere but carries a message in its name.
func noticeProfile(msg string) compose.Profile {
	return compose.Profile{Upstream: spec.Upstream{
		Name: "⛔ " + msg, Protocol: spec.ProtoVLESS, Address: "127.0.0.1", Port: 1, UUID: "00000000-0000-4000-8000-000000000000",
		Transport: spec.Transport{Type: spec.TransportTCP}, Security: spec.Security{Type: spec.SecurityNone},
	}}
}

// serveSub is the link clients fetch.
func (s *Server) serveSub(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	u, err := s.userByToken(r.Context(), r.PathValue("token"))
	if err != nil {
		metrics.SubRequests.WithLabelValues("none", "not_found").Inc()
		http.NotFound(w, r)
		return
	}
	format := r.PathValue("format")
	if format == "" {
		format = r.URL.Query().Get("format")
	}

	doc, err := s.buildSub(r.Context(), u, r.UserAgent(), format, deviceOf(r))
	if err != nil {
		metrics.SubRequests.WithLabelValues(subFormatLabel(format), "error").Inc()
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	label := subFormatLabel(doc.Format)
	metrics.SubRequests.WithLabelValues(label, "ok").Inc()
	metrics.SubSeconds.WithLabelValues(label).Observe(time.Since(start).Seconds())
	metrics.SubBytes.WithLabelValues(label).Add(float64(len(doc.Body)))
	_ = s.Queries.TouchSub(r.Context(), db.TouchSubParams{ID: u.ID, SubLastUa: truncate(r.UserAgent(), 200)})

	for k, v := range doc.Headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", doc.ContentType)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(doc.Body)
}

// subFormatLabel keeps what a client typed out of metric labels.
func subFormatLabel(format string) string {
	if format == "" {
		return "auto"
	}
	if slices.Contains(share.Formats, format) {
		return format
	}
	return "unknown"
}

// truncate cuts s to n bytes.
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// previewSub shows an admin what a given user would receive from a given client.
func (s *Server) previewSub(w http.ResponseWriter, r *http.Request) {
	id := int64Param(r, "user_id")
	if id == nil {
		invalid(w, "user_id", "pick a user to preview")
		return
	}
	u, err := s.Queries.GetUser(r.Context(), *id)
	if err != nil {
		dbError(w, err)
		return
	}
	doc, err := s.buildSub(r.Context(), u, r.URL.Query().Get("ua"), r.URL.Query().Get("format"), deviceInfo{HWID: "preview"})
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	ok(w, map[string]any{"format": doc.Format, "content_type": doc.ContentType, "content": string(doc.Body), "headers": doc.Headers})
}

// listTemplates lists subscription templates.
func (s *Server) listTemplates(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Queries.ListSubTemplates(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	ok(w, orEmpty(rows))
}

// templateRequest is the JSON body for a template.
type templateRequest struct {
	Name   string          `json:"name"`
	Format string          `json:"format"`
	Patch  json.RawMessage `json:"patch"`
}

// clean validates a template request.
func (t *templateRequest) clean() error {
	t.Name = strings.TrimSpace(t.Name)
	if t.Name == "" {
		return spec.Invalid("name", "name is required")
	}
	if !contains(share.Formats, t.Format) {
		return spec.Invalid("format", "unknown format")
	}
	var probe map[string]any
	if err := json.Unmarshal(t.Patch, &probe); err != nil {
		return spec.Invalid("patch", "the patch must be a json object")
	}
	return nil
}

// contains reports whether list has v.
func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// createTemplate adds a template.
func (s *Server) createTemplate(w http.ResponseWriter, r *http.Request) {
	var req templateRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if err := req.clean(); err != nil {
		badInput(w, err)
		return
	}
	t, err := s.Queries.CreateSubTemplate(r.Context(), db.CreateSubTemplateParams{Name: req.Name, Format: req.Format, Patch: req.Patch})
	if err != nil {
		dbError(w, err)
		return
	}
	s.audit(r, "template.create", t.Name, nil)
	created(w, t)
}

// updateTemplate edits a template.
func (s *Server) updateTemplate(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	var req templateRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if err := req.clean(); err != nil {
		badInput(w, err)
		return
	}
	t, err := s.Queries.UpdateSubTemplate(r.Context(), db.UpdateSubTemplateParams{ID: id, Name: req.Name, Format: req.Format, Patch: req.Patch})
	if err != nil {
		dbError(w, err)
		return
	}
	s.audit(r, "template.update", t.Name, nil)
	ok(w, t)
}

// deleteTemplate removes a template.
func (s *Server) deleteTemplate(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	rows, err := s.Queries.DeleteSubTemplate(r.Context(), id)
	if err != nil {
		dbError(w, err)
		return
	}
	if rows == 0 {
		notFound(w, "not found")
		return
	}
	noContent(w)
}

// listSubRules lists user agent rules.
func (s *Server) listSubRules(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Queries.ListSubRules(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	ok(w, orEmpty(rows))
}

// subRuleRequest is the JSON body for a user agent rule.
type subRuleRequest struct {
	Name       string `json:"name"`
	UARegex    string `json:"ua_regex"`
	Format     string `json:"format"`
	TemplateID *int64 `json:"template_id"`
	Enabled    *bool  `json:"enabled"`
	Sort       int32  `json:"sort"`
}

// clean validates a rule request.
func (q *subRuleRequest) clean() error {
	if q.UARegex == "" {
		return spec.Invalid("ua_regex", "the pattern is required")
	}
	if _, err := regexp.Compile(q.UARegex); err != nil {
		return spec.Invalid("ua_regex", "not a valid regular expression: %s", err)
	}
	if !contains(share.Formats, q.Format) {
		return spec.Invalid("format", "unknown format")
	}
	return nil
}

// createSubRule adds a user agent rule.
func (s *Server) createSubRule(w http.ResponseWriter, r *http.Request) {
	var req subRuleRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if err := req.clean(); err != nil {
		badInput(w, err)
		return
	}
	rule, err := s.Queries.CreateSubRule(r.Context(), db.CreateSubRuleParams{
		Name: req.Name, UaRegex: req.UARegex, Format: req.Format, TemplateID: req.TemplateID, Enabled: req.Enabled == nil || *req.Enabled, Sort: req.Sort,
	})
	if err != nil {
		dbError(w, err)
		return
	}
	s.audit(r, "subrule.create", rule.Name, nil)
	created(w, rule)
}

// updateSubRule edits a user agent rule.
func (s *Server) updateSubRule(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	var req subRuleRequest
	if err := decode(r, &req); err != nil {
		badRequest(w, err.Error())
		return
	}
	if err := req.clean(); err != nil {
		badInput(w, err)
		return
	}
	rule, err := s.Queries.UpdateSubRule(r.Context(), db.UpdateSubRuleParams{
		ID: id, Name: req.Name, UaRegex: req.UARegex, Format: req.Format, TemplateID: req.TemplateID, Enabled: req.Enabled == nil || *req.Enabled, Sort: req.Sort,
	})
	if err != nil {
		dbError(w, err)
		return
	}
	s.audit(r, "subrule.update", rule.Name, nil)
	ok(w, rule)
}

// deleteSubRule removes a user agent rule.
func (s *Server) deleteSubRule(w http.ResponseWriter, r *http.Request) {
	id, good := pathID(r)
	if !good {
		badRequest(w, "invalid id in path")
		return
	}
	rows, err := s.Queries.DeleteSubRule(r.Context(), id)
	if err != nil {
		dbError(w, err)
		return
	}
	if rows == 0 {
		notFound(w, "not found")
		return
	}
	noContent(w)
}

// app is a client the portal offers an import button for.
type app struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Platforms []string `json:"platforms"`
	Import    string   `json:"import"`   // deep link, with {url} and {name} filled in
	Download  string   `json:"download"` // where to get the app
	Format    string   `json:"format"`   // what the app reads best, for the manual link
}

// apps is the catalog of clients the portal knows.
var apps = []app{
	{ID: "hiddify", Name: "Hiddify", Platforms: []string{"android", "ios", "windows", "macos", "linux"}, Import: "hiddify://import/{url}#{name}", Download: "https://github.com/hiddify/hiddify-app/releases", Format: share.FormatLinks},
	{ID: "singbox", Name: "sing-box", Platforms: []string{"android", "ios", "macos"}, Import: "sing-box://import-remote-profile?url={urlenc}#{name}", Download: "https://sing-box.sagernet.org/clients/", Format: share.FormatSingbox},
	{ID: "v2rayng", Name: "v2rayNG", Platforms: []string{"android"}, Import: "v2rayng://install-config?url={urlenc}#{name}", Download: "https://github.com/2dust/v2rayNG/releases", Format: share.FormatLinks},
	{ID: "v2rayn", Name: "v2rayN", Platforms: []string{"windows", "linux", "macos"}, Download: "https://github.com/2dust/v2rayN/releases", Format: share.FormatLinks},
	{ID: "streisand", Name: "Streisand", Platforms: []string{"ios", "macos"}, Import: "streisand://import/{url}", Download: "https://apps.apple.com/app/streisand/id6450534064", Format: share.FormatLinks},
	{ID: "happ", Name: "Happ", Platforms: []string{"ios", "android", "macos", "windows"}, Import: "happ://add/{url}", Download: "https://www.happ.su/", Format: share.FormatLinks},
	{ID: "shadowrocket", Name: "Shadowrocket", Platforms: []string{"ios"}, Import: "shadowrocket://add/sub://{b64}?remark={name}", Download: "https://apps.apple.com/app/shadowrocket/id932747118", Format: share.FormatLinks},
	{ID: "clashverge", Name: "Clash Verge Rev", Platforms: []string{"windows", "macos", "linux"}, Import: "clash://install-config?url={urlenc}&name={name}", Download: "https://github.com/clash-verge-rev/clash-verge-rev/releases", Format: share.FormatClash},
	{ID: "flclash", Name: "FlClash", Platforms: []string{"android", "windows", "macos", "linux"}, Import: "clash://install-config?url={urlenc}", Download: "https://github.com/chen08209/FlClash/releases", Format: share.FormatClash},
	{ID: "nekobox", Name: "NekoBox", Platforms: []string{"android"}, Import: "sn://subscription?url={urlenc}&name={name}", Download: "https://github.com/MatsuriDayo/NekoBoxForAndroid/releases", Format: share.FormatLinks},
}

// portal serves the data behind a user's self service page. The token is the only credential.
func (s *Server) portal(w http.ResponseWriter, r *http.Request) {
	u, err := s.userByToken(r.Context(), r.PathValue("token"))
	metrics.PortalViews.WithLabelValues(map[bool]string{true: "ok", false: "not_found"}[err == nil]).Inc()
	if err != nil {
		notFound(w, "no such subscription")
		return
	}
	set := defaultSub()
	if err := s.loadSetting(r.Context(), "subscription", &set); err != nil {
		internalError(w, err)
		return
	}

	profiles, err := s.profilesOf(r.Context(), u)
	if err != nil {
		internalError(w, err)
		return
	}
	links := make([]linkResponse, 0, len(profiles))
	for _, p := range profiles {
		if r, ok := newLinkResponse(p); ok {
			links = append(links, r)
		}
	}

	subURL := s.publicURL(r) + "/sub/" + u.SubToken
	formats := map[string]string{}
	for _, f := range share.Formats {
		formats[f] = subURL + "/" + f
	}
	ok(w, map[string]any{
		"user": map[string]any{
			"username": u.Username, "status": u.Status, "traffic_used": u.TrafficUsed, "traffic_limit": u.TrafficLimit,
			"expire_at": u.ExpireAt, "reset_strategy": u.ResetStrategy, "last_reset": u.LastReset, "on_hold_days": u.OnHoldDays,
			"device_limit": u.DeviceLimit,
		},
		"sub_url": subURL, "formats": formats, "links": links, "apps": apps,
		"title": set.Title, "support_url": set.SupportURL, "announce": set.Announce,
		"telegram_bot": s.Notify.BotName(r.Context()), "token": u.SubToken,
		"brand": map[string]string{"logo_url": set.LogoURL, "accent": set.Accent, "footer": set.Footer},
	})
}
