package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"frostbite/internal/compose"
	"frostbite/internal/notify"
	"frostbite/internal/spec"
)

// registerSettings registers panel settings endpoints.
func (s *Server) registerSettings(mux authMux) {
	mux.Admin("GET /settings", s.getSettings)
	mux.Admin("PUT /settings/subscription", s.putSubSettings)
	mux.Admin("PUT /settings/routing", s.putRouting)
	mux.Admin("GET /settings/audit-size", s.auditSize)
	mux.Admin("GET /settings/notifications", s.getNotifications)
	mux.Admin("PUT /settings/notifications", s.putNotifications)
	mux.Admin("POST /settings/notifications/test", s.testNotifications)
}

// SubSettings controls what subscriptions say and how clients treat them.
type SubSettings struct {
	Title          string `json:"title"`
	SupportURL     string `json:"support_url"`
	WebPageURL     string `json:"web_page_url"`
	Announce       string `json:"announce"`
	UpdateHours    int    `json:"update_hours"`
	DefaultFormat  string `json:"default_format"`  // auto or one of the formats
	NoticeProfiles bool   `json:"notice_profiles"` // show inactive users a profile that says why
	SortByCountry  bool   `json:"sort_by_country"`
	HideBridges    bool   `json:"hide_bridges"`
	LogoURL        string `json:"logo_url"` // shown on the user page, https or a data image
	Accent         string `json:"accent"`   // hex colour for the user page
	Footer         string `json:"footer"`
}

// brandingOK reports whether a branding value is safe to put on the public user page.
func (s SubSettings) brandingOK() string {
	if err := s.brandingErr(); err != nil {
		return err.Error()
	}
	return ""
}

// brandingErr is brandingOK with the field the problem is in.
func (s SubSettings) brandingErr() error {
	if s.Accent != "" && !hexColor.MatchString(s.Accent) {
		return spec.Invalid("accent", "the accent colour must look like #7cc8f7")
	}
	if s.LogoURL != "" && !strings.HasPrefix(s.LogoURL, "https://") && !strings.HasPrefix(s.LogoURL, "http://") && !strings.HasPrefix(s.LogoURL, "data:image/") {
		return spec.Invalid("logo_url", "the logo must be an http(s) address or an image data url")
	}
	if len(s.LogoURL) > 300_000 {
		return spec.Invalid("logo_url", "the logo is too large")
	}
	if len(s.Footer) > 500 {
		return spec.Invalid("footer", "the footer can be at most 500 characters")
	}
	return nil
}

// hexColor matches #rgb and #rrggbb.
var hexColor = regexp.MustCompile(`^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)

// defaultSub is what a fresh panel starts with.
func defaultSub() SubSettings {
	return SubSettings{Title: "Frostbite", UpdateHours: 6, DefaultFormat: "auto", NoticeProfiles: true}
}

// loadSetting reads a json setting into v, leaving v alone when it was never saved.
func (s *Server) loadSetting(ctx context.Context, key string, v any) error {
	raw, err := s.Queries.GetSetting(ctx, key)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// saveSetting stores a json setting.
func (s *Server) saveSetting(ctx context.Context, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.Queries.SetSetting(ctx, dbSetSetting(key, raw))
}

// getSettings returns every group of settings.
func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	sub := defaultSub()
	var routing compose.Routing
	if err := s.loadSetting(r.Context(), "subscription", &sub); err != nil {
		internalError(w, err)
		return
	}
	if err := s.loadSetting(r.Context(), "routing", &routing); err != nil {
		internalError(w, err)
		return
	}
	ok(w, map[string]any{"subscription": sub, "routing": routing, "public_url": s.publicURL(r)})
}

// putSubSettings saves the subscription settings.
func (s *Server) putSubSettings(w http.ResponseWriter, r *http.Request) {
	sub := defaultSub()
	if err := decode(r, &sub); err != nil {
		badRequest(w, err.Error())
		return
	}
	if sub.UpdateHours < 1 {
		sub.UpdateHours = 1
	}
	if err := sub.brandingErr(); err != nil {
		badInput(w, err)
		return
	}
	if err := s.saveSetting(r.Context(), "subscription", sub); err != nil {
		internalError(w, err)
		return
	}
	s.audit(r, "settings.subscription", "", nil)
	ok(w, sub)
}

// putRouting saves the panel wide routing switches.
func (s *Server) putRouting(w http.ResponseWriter, r *http.Request) {
	var rt compose.Routing
	if err := decode(r, &rt); err != nil {
		badRequest(w, err.Error())
		return
	}
	if err := s.saveSetting(r.Context(), "routing", rt); err != nil {
		internalError(w, err)
		return
	}
	s.Hub.MarkDirty()
	s.audit(r, "settings.routing", "", nil)
	ok(w, rt)
}

// auditSize is a cheap check the UI uses to decide whether to show the audit tab.
func (s *Server) auditSize(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Queries.ListAudit(r.Context(), dbListAudit(1))
	if err != nil {
		internalError(w, err)
		return
	}
	ok(w, map[string]bool{"any": len(rows) > 0})
}

// notificationsView is the settings as the UI sees them: the bot token is never sent back.
type notificationsView struct {
	notify.Settings
	TokenSet bool `json:"token_set"`
}

// getNotifications returns the notification settings.
func (s *Server) getNotifications(w http.ResponseWriter, r *http.Request) {
	set := s.Notify.Settings(r.Context())
	view := notificationsView{Settings: set, TokenSet: set.Telegram.Token != ""}
	view.Telegram.Token = ""
	ok(w, view)
}

// putNotifications saves the notification settings.
func (s *Server) putNotifications(w http.ResponseWriter, r *http.Request) {
	cur := s.Notify.Settings(r.Context())
	set := notify.DefaultSettings()
	if err := decode(r, &set); err != nil {
		badRequest(w, err.Error())
		return
	}
	if set.Telegram.Token == "" {
		set.Telegram.Token = cur.Telegram.Token
	}
	for i, h := range set.Webhooks {
		u, err := url.Parse(h.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			invalid(w, fmt.Sprintf("webhooks.%d.url", i), "the address must be an http or https url")
			return
		}
		set.Webhooks[i].Events = onlyKnown(h.Events)
	}
	set.Telegram.Events = onlyKnown(set.Telegram.Events)
	for _, p := range set.UsagePercent {
		if p < 1 || p > 99 {
			invalid(w, "usage_percent", "usage thresholds are percentages between 1 and 99")
			return
		}
	}
	for _, d := range set.ExpireDays {
		if d < 1 || d > 15 {
			invalid(w, "expire_days", "expiry warnings can be between 1 and 15 days before")
			return
		}
	}
	if err := s.saveSetting(r.Context(), "notifications", set); err != nil {
		internalError(w, err)
		return
	}
	s.Notify.Invalidate()
	s.audit(r, "settings.notifications", "", nil)
	view := notificationsView{Settings: set, TokenSet: set.Telegram.Token != ""}
	view.Telegram.Token = ""
	ok(w, view)
}

// onlyKnown drops event names the panel does not produce.
func onlyKnown(list []string) []string {
	out := []string{}
	for _, k := range list {
		if slices.Contains(notify.Kinds, k) {
			out = append(out, k)
		}
	}
	return out
}

// testNotifications sends a test message everywhere and reports each outcome.
func (s *Server) testNotifications(w http.ResponseWriter, r *http.Request) {
	ok(w, s.Notify.SendTest(r.Context()))
}
