// Package notify tells people about things: webhooks for machines, Telegram for humans.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"frostbite/internal/db"
	"frostbite/internal/metrics"
)

// Event kinds.
const (
	UserExpiring = "user.expiring"
	UserUsage    = "user.usage"
	UserLimited  = "user.limited"
	UserExpired  = "user.expired"
	UserBlocked  = "user.blocked"
	NodeOffline  = "node.offline"
	NodeOnline   = "node.online"
	Test         = "test"
)

// Kinds lists every event the UI can subscribe a target to.
var Kinds = []string{UserExpiring, UserUsage, UserLimited, UserExpired, UserBlocked, NodeOffline, NodeOnline}

// userKinds are the events a user themselves may be told about.
var userKinds = []string{UserExpiring, UserUsage, UserLimited, UserExpired}

// Event is one thing that happened.
type Event struct {
	Kind string         `json:"kind"`
	At   time.Time      `json:"at"`
	User *UserInfo      `json:"user,omitempty"`
	Node *NodeInfo      `json:"node,omitempty"`
	Data map[string]any `json:"data,omitempty"`
}

// UserInfo is the part of a user an alert needs.
type UserInfo struct {
	ID         int64      `json:"id"`
	Username   string     `json:"username"`
	Status     string     `json:"status"`
	Used       int64      `json:"traffic_used"`
	Limit      int64      `json:"traffic_limit"`
	ExpireAt   *time.Time `json:"expire_at"`
	TelegramID *int64     `json:"telegram_id,omitempty"`
}

// NodeInfo is the part of a node an alert needs.
type NodeInfo struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Daemon string `json:"daemon,omitempty"`
}

// UserOf summarises a user.
func UserOf(u db.User) *UserInfo {
	return &UserInfo{ID: u.ID, Username: u.Username, Status: u.Status, Used: u.TrafficUsed, Limit: u.TrafficLimit, ExpireAt: u.ExpireAt, TelegramID: u.TelegramID}
}

// Webhook is one machine endpoint.
type Webhook struct {
	URL     string   `json:"url"`
	Secret  string   `json:"secret"`
	Events  []string `json:"events"` // empty means all
	Enabled bool     `json:"enabled"`
}

// Telegram configures the bot.
type Telegram struct {
	Enabled     bool     `json:"enabled"`
	Token       string   `json:"token"`
	AdminIDs    []int64  `json:"admin_ids"`
	Events      []string `json:"events"`       // for admins, empty means all
	NotifyUsers bool     `json:"notify_users"` // also message users who linked their account
	APIBase     string   `json:"api_base"`     // for tests and self hosted bot servers
}

// Settings is everything the notification system is configured with.
type Settings struct {
	Webhooks     []Webhook `json:"webhooks"`
	Telegram     Telegram  `json:"telegram"`
	ExpireDays   []int     `json:"expire_days"`
	UsagePercent []int     `json:"usage_percent"`
}

// DefaultSettings is what a fresh panel starts with.
func DefaultSettings() Settings {
	return Settings{Webhooks: []Webhook{}, ExpireDays: []int{3, 1}, UsagePercent: []int{80, 95}, Telegram: Telegram{AdminIDs: []int64{}}}
}

// Result is the outcome of one delivery attempt in a test.
type Result struct {
	Target string `json:"target"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

// Service queues events and delivers them.
type Service struct {
	q      *db.Queries
	http   *http.Client
	queue  chan Event
	online func(daemonID int64) bool
	dirty  func()
	base   string

	mu       sync.Mutex
	cached   Settings
	cachedAt time.Time
	seen     map[int64]*nodeState
	botName  string
	botAt    time.Time
}

// nodeState tracks a daemon between scans so flapping does not spam.
type nodeState struct {
	down      time.Time
	announced bool
}

// New creates a service. online reports whether a daemon is connected, dirty asks for a spec rebuild after the bot changes a user.
func New(q *db.Queries, online func(int64) bool, dirty func()) *Service {
	return &Service{
		q: q, online: online, dirty: dirty,
		http:  &http.Client{Timeout: 10 * time.Second},
		queue: make(chan Event, 256),
		seen:  map[int64]*nodeState{},
	}
}

// QueueLen is how many events wait for delivery.
func (s *Service) QueueLen() int { return len(s.queue) }

// Emit queues an event without ever blocking the caller.
func (s *Service) Emit(ev Event) {
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	metrics.NotifyEmitted.WithLabelValues(ev.Kind).Inc()
	select {
	case s.queue <- ev:
	default:
		metrics.NotifyDropped.Inc()
		slog.Warn("notify: queue is full, dropping an event", "kind", ev.Kind)
	}
}

// Settings returns the current configuration, reading it at most every few seconds.
func (s *Service) Settings(ctx context.Context) Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.cachedAt) < 5*time.Second && s.cachedAt != (time.Time{}) {
		return s.cached
	}
	set := DefaultSettings()
	raw, err := s.q.GetSetting(ctx, "notifications")
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		slog.Warn("notify: reading settings failed", "err", err)
		return s.cached
	default:
		if err := json.Unmarshal(raw, &set); err != nil {
			slog.Warn("notify: settings are unreadable", "err", err)
		}
	}
	s.cached, s.cachedAt = set, time.Now()
	return set
}

// Invalidate makes the next read go to the database, after settings were saved.
func (s *Service) Invalidate() {
	s.mu.Lock()
	s.cachedAt = time.Time{}
	s.mu.Unlock()
}

// Run delivers queued events and scans for time based ones until ctx ends.
func (s *Service) Run(ctx context.Context) {
	scan := time.NewTicker(time.Minute)
	defer scan.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-s.queue:
			for _, r := range s.deliver(ctx, ev) {
				if !r.OK {
					slog.Warn("notify: delivery failed", "kind", ev.Kind, "target", r.Target, "err", r.Error)
				}
			}
		case <-scan.C:
			s.Scan(ctx)
		}
	}
}

// deliver sends an event to every target that wants it and reports what happened.
func (s *Service) deliver(ctx context.Context, ev Event) []Result {
	set := s.Settings(ctx)
	var out []Result
	// record notes how one delivery went
	record := func(channel string, start time.Time, r Result) {
		result := "ok"
		if !r.OK {
			result = "error"
		}
		metrics.NotifyDeliveries.WithLabelValues(channel, ev.Kind, result).Inc()
		metrics.NotifySeconds.WithLabelValues(channel).Observe(time.Since(start).Seconds())
	}

	for _, w := range set.Webhooks {
		if !w.Enabled || w.URL == "" || !wants(w.Events, ev.Kind) {
			continue
		}
		start := time.Now()
		out = append(out, Result{Target: w.URL, OK: true})
		if err := s.postWebhook(ctx, w, ev); err != nil {
			out[len(out)-1] = Result{Target: w.URL, Error: err.Error()}
		}
		record("webhook", start, out[len(out)-1])
	}

	t := set.Telegram
	if t.Enabled && t.Token != "" {
		text := Text(ev)
		if wants(t.Events, ev.Kind) || ev.Kind == Test {
			for _, id := range t.AdminIDs {
				start := time.Now()
				r := Result{Target: fmt.Sprintf("telegram:%d", id), OK: true}
				if err := s.send(ctx, t, id, text); err != nil {
					r = Result{Target: r.Target, Error: err.Error()}
				}
				record("telegram", start, r)
				out = append(out, r)
			}
		}
		if t.NotifyUsers && ev.User != nil && ev.User.TelegramID != nil && slices.Contains(userKinds, ev.Kind) {
			start := time.Now()
			r := Result{Target: fmt.Sprintf("telegram:%d", *ev.User.TelegramID), OK: true}
			if err := s.send(ctx, t, *ev.User.TelegramID, UserText(ev)); err != nil {
				r = Result{Target: r.Target, Error: err.Error()}
			}
			record("telegram_user", start, r)
			out = append(out, r)
		}
	}
	return out
}

// wants reports whether a subscription list includes kind. An empty list means everything.
func wants(list []string, kind string) bool {
	return len(list) == 0 || slices.Contains(list, kind)
}

// SendTest delivers a test event to every target and reports each outcome.
func (s *Service) SendTest(ctx context.Context) []Result {
	res := s.deliver(ctx, Event{Kind: Test, At: time.Now(), Data: map[string]any{"message": "Hello from Frostbite."}})
	if res == nil {
		return []Result{}
	}
	return res
}

// postWebhook sends an event as signed json, retrying a couple of times.
func (s *Service) postWebhook(ctx context.Context, w Webhook, ev Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}

	var last error
	for i, wait := range []time.Duration{0, time.Second, 5 * time.Second} {
		if i > 0 {
			metrics.NotifyRetries.Inc()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Frostbite")
		req.Header.Set("X-Frostbite-Event", ev.Kind)
		if w.Secret != "" {
			mac := hmac.New(sha256.New, []byte(w.Secret))
			mac.Write(body)
			req.Header.Set("X-Frostbite-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		}
		resp, err := s.http.Do(req)
		if err != nil {
			last = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode/100 == 2 {
			return nil
		}
		last = fmt.Errorf("the endpoint answered %s", resp.Status)
		if resp.StatusCode/100 == 4 {
			return last // retrying a rejection will not help
		}
	}
	return last
}

// Text renders an event for an administrator.
func Text(ev Event) string {
	u, n := ev.User, ev.Node
	switch ev.Kind {
	case UserExpiring:
		return fmt.Sprintf("⏳ <b>%s</b> expires in %v days.", esc(u.Username), ev.Data["days_left"])
	case UserUsage:
		return fmt.Sprintf("📈 <b>%s</b> has used %v%% of their traffic.", esc(u.Username), ev.Data["percent"])
	case UserLimited:
		return fmt.Sprintf("🚦 <b>%s</b> reached their traffic limit.", esc(u.Username))
	case UserExpired:
		return fmt.Sprintf("📅 <b>%s</b> has expired.", esc(u.Username))
	case UserBlocked:
		return fmt.Sprintf("🛡 <b>%s</b> was cut off for using too many IPs (%v).", esc(u.Username), ev.Data["ips"])
	case NodeOffline:
		return fmt.Sprintf("🔴 <b>%s</b> (%s) went offline.", esc(n.Name), esc(n.Daemon))
	case NodeOnline:
		return fmt.Sprintf("🟢 <b>%s</b> (%s) is back online.", esc(n.Name), esc(n.Daemon))
	case Test:
		return "✅ Frostbite can reach you here."
	}
	return esc(ev.Kind)
}

// UserText renders an event for the user it is about.
func UserText(ev Event) string {
	switch ev.Kind {
	case UserExpiring:
		return fmt.Sprintf("⏳ Your subscription ends in %v days.", ev.Data["days_left"])
	case UserUsage:
		return fmt.Sprintf("📈 You have used %v%% of your traffic.", ev.Data["percent"])
	case UserLimited:
		return "🚦 You reached your traffic limit."
	case UserExpired:
		return "📅 Your subscription has expired."
	}
	return Text(ev)
}

// esc escapes text for Telegram's html mode.
func esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
