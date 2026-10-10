// Package metrics holds everything the panel exposes to Prometheus: counters bumped where things happen,
// and a collector that reads the rest from the database and the hub when Prometheus asks.
package metrics

import (
	"crypto/subtle"
	"net/http"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const ns = "frostbite"

// Version is the panel build version, set at link time.
var Version = "dev"

// Registry is where every panel metric lives, separate from the global one so tests never collide.
var Registry = prometheus.NewRegistry()

var started = time.Now()

// latency buckets suit calls that take from a millisecond to a few seconds.
var latency = []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30}

// slow buckets suit work that takes seconds to minutes.
var slow = []float64{.01, .05, .1, .5, 1, 2.5, 5, 10, 30, 60, 120, 300}

func counter(name, help string, labels ...string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: name, Help: help}, labels)
	Registry.MustRegister(c)
	return c
}

func histogram(name, help string, buckets []float64, labels ...string) *prometheus.HistogramVec {
	h := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns, Name: name, Help: help, Buckets: buckets,
	}, labels)
	Registry.MustRegister(h)
	return h
}

func counter0(name, help string) prometheus.Counter {
	c := prometheus.NewCounter(prometheus.CounterOpts{Namespace: ns, Name: name, Help: help})
	Registry.MustRegister(c)
	return c
}

func histogram0(name, help string, buckets []float64) prometheus.Histogram {
	h := prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: ns, Name: name, Help: help, Buckets: buckets})
	Registry.MustRegister(h)
	return h
}

func gauge(name, help string) prometheus.Gauge {
	g := prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: name, Help: help})
	Registry.MustRegister(g)
	return g
}

// HTTP traffic served by the panel.
var (
	HTTPRequests  = counter("http_requests_total", "Requests served, by route pattern and status code.", "method", "route", "code")
	HTTPSeconds   = histogram("http_request_duration_seconds", "Time to answer a request. Daemon links and other upgraded connections are left out.", latency, "method", "route")
	HTTPRespBytes = counter("http_response_bytes_total", "Bytes written in response bodies.", "route")
	HTTPReqBytes  = counter("http_request_bytes_total", "Bytes received in request bodies, as declared by the client.", "route")
	HTTPInflight  = gauge("http_requests_in_flight", "Requests being handled right now.")
	HTTPPanics    = counter("http_panics_total", "Handlers that panicked.", "route")
)

// Authentication and administration.
var (
	AuthLogins    = counter("auth_logins_total", "Sign in attempts by outcome.", "result")
	AuthRejected  = counter("auth_rejected_requests_total", "Requests refused for missing or bad credentials, by credential kind.", "credential")
	AuthTokenUsed = counter0("auth_api_token_requests_total", "Requests authenticated with an API token.")
	AuditEvents   = counter("audit_events_total", "Administrator actions written to the audit log.", "action")
)

// The daemon link.
var (
	LinkConnections    = counter("link_connections_total", "Daemons that connected.", "kind")
	LinkDisconnections = counter("link_disconnections_total", "Daemons that disconnected.", "kind")
	LinkRejected       = counter("link_rejected_total", "Daemon connections refused before they started.", "reason")
	LinkSessionSeconds = histogram("link_session_duration_seconds", "How long a daemon stayed connected.", []float64{1, 5, 15, 30, 60, 300, 900, 3600, 6 * 3600, 24 * 3600, 7 * 24 * 3600}, "kind")
	LinkMessagesIn     = counter("link_messages_received_total", "Frames received from daemons.", "kind", "type")
	LinkMessagesOut    = counter("link_messages_sent_total", "Frames sent to daemons.", "kind", "type")
	LinkBytesIn        = counter("link_received_bytes_total", "Bytes received from daemons.", "kind")
	LinkBytesOut       = counter("link_sent_bytes_total", "Bytes sent to daemons.", "kind")
	LinkBadFrames      = counter("link_bad_frames_total", "Frames from daemons that could not be read.", "kind")
	LinkDropped        = counter("link_dropped_total", "Daemons dropped because they could not keep up.", "kind")
)

// Pushing desired state to daemons.
var (
	HubRebuilds     = counter("hub_rebuilds_total", "Passes that recomputed daemon specs.", "result")
	HubRebuildSecs  = histogram0("hub_rebuild_duration_seconds", "Time to recompute every daemon spec.", latency)
	SpecsBuilt      = counter("spec_builds_total", "Daemon specs computed, by whether they were accepted.", "result")
	SpecRevisions   = counter0("spec_revisions_total", "Times a daemon's spec changed and its revision went up.")
	SpecPushes      = counter("spec_pushes_total", "Specs sent to connected daemons.", "kind")
	SpecAcks        = counter("spec_acks_total", "Answers from daemons after a spec was pushed.", "kind", "result")
	CommandsSent    = counter("daemon_commands_total", "Commands sent to daemons.", "name", "result")
	CommandSeconds  = histogram("daemon_command_duration_seconds", "Time a daemon took to answer a command.", latency, "name")
	DaemonReports   = counter("daemon_reports_total", "Usage and health reports received.", "kind", "type")
	IngestSeconds   = histogram0("usage_ingest_duration_seconds", "Time to book one usage report.", latency)
	IngestUnknown   = counter0("usage_unknown_users_total", "Usage entries that matched no user, for example one that was just deleted.")
	TrafficBilled   = counter("traffic_billed_bytes_total", "Traffic booked against users after the node multiplier.", "node_id", "node", "direction")
	TrafficRaw      = counter("traffic_raw_bytes_total", "Traffic reported by daemons before the node multiplier.", "node_id", "node")
	IPLimitBlocks   = counter0("ip_limit_blocks_total", "Users cut off for using more addresses than allowed.")
	LimitHits       = counter0("traffic_limit_hits_total", "Usage reports that left a user at or over their traffic limit.")
	OnlineSnapshots = counter0("online_reports_total", "Reports of who is connected.")
)

// Limits, expiry and resets.
var (
	QuotaPasses      = counter0("quota_passes_total", "Enforcement passes run.")
	QuotaPassSeconds = histogram0("quota_pass_duration_seconds", "Time one enforcement pass took.", latency)
	QuotaChanges     = counter("quota_user_changes_total", "Users changed by enforcement.", "change")
	QuotaErrors      = counter("quota_errors_total", "Enforcement steps that failed.", "step")
	Housekeeping     = counter("housekeeping_runs_total", "Hourly cleanup runs.", "task", "result")
)

// Alerts and the Telegram bot.
var (
	NotifyEmitted    = counter("notify_events_total", "Events raised.", "kind")
	NotifyDropped    = counter0("notify_events_dropped_total", "Events dropped because the queue was full.")
	NotifyDeliveries = counter("notify_deliveries_total", "Deliveries to a webhook or Telegram chat.", "channel", "kind", "result")
	NotifySeconds    = histogram("notify_delivery_duration_seconds", "Time to deliver one event to one target.", latency, "channel")
	NotifyRetries    = counter0("notify_webhook_retries_total", "Webhook attempts that were repeated.")
	NotifyScans      = counter("notify_scans_total", "Scans for expiring users and quiet daemons.", "result")
	TelegramCalls    = counter("telegram_api_calls_total", "Calls to the Telegram Bot API.", "method", "result")
	TelegramSeconds  = histogram("telegram_api_call_duration_seconds", "Time a Bot API call took.", latency, "method")
	BotUpdates       = counter0("telegram_bot_updates_total", "Messages the bot received.")
	BotCommands      = counter("telegram_bot_commands_total", "Commands the bot answered.", "scope")
)

// Subscriptions and the user page.
var (
	SubRequests = counter("subscription_requests_total", "Subscription downloads by format and outcome.", "format", "result")
	SubSeconds  = histogram("subscription_render_duration_seconds", "Time to render a subscription.", latency, "format")
	SubBytes    = counter("subscription_bytes_total", "Bytes of subscription documents served.", "format")
	PortalViews = counter("portal_requests_total", "Requests for a user's self service page data.", "result")
	Devices     = counter("device_checks_total", "Device limit checks while serving a subscription.", "result")
)

// Backups, imports and WARP.
var (
	BackupRuns     = counter("backup_runs_total", "Backups made or restored, by trigger and outcome.", "trigger", "result")
	BackupSeconds  = histogram("backup_duration_seconds", "Time a backup or restore took.", slow, "trigger")
	BackupBytes    = counter0("backup_written_bytes_total", "Bytes written into backup files.")
	ImportRuns     = counter("import_runs_total", "User imports.", "source", "result")
	ImportedUsers  = counter("import_users_total", "Users created or skipped by imports.", "outcome")
	WarpOperations = counter("warp_operations_total", "Cloudflare WARP account operations.", "op", "result")
)

// Database access from the panel.
var (
	DBQueries = counter("db_queries_total", "Queries run, by sqlc query name.", "query", "result")
	DBSeconds = histogram("db_query_duration_seconds", "Time a query took.", latency, "query")
)

// collection bookkeeping, see collector.go
var (
	collectSeconds = prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "collect_duration_seconds", Help: "Time the last refresh of a group of database metrics took."}, []string{"group"})
	collectErrors  = counter("collect_failures_total", "Refreshes of database metrics that failed.", "group")
	collectLast    = prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "collect_last_success_timestamp_seconds", Help: "When a group of database metrics was last refreshed."}, []string{"group"})
)

func init() {
	Registry.MustRegister(
		collectors.NewGoCollector(collectors.WithGoCollectorRuntimeMetrics(collectors.MetricsAll)),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{Namespace: ns}),
		collectSeconds, collectLast,
	)

	goVersion := runtime.Version()
	revision, modified := "", ""
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
				if len(revision) > 12 {
					revision = revision[:12]
				}
			case "vcs.modified":
				modified = s.Value
			}
		}
	}
	build := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: ns, Name: "build_info", Help: "Always 1, labelled with what this binary was built from.",
		ConstLabels: prometheus.Labels{"version": Version, "go_version": goVersion, "revision": revision, "modified": modified, "goos": runtime.GOOS, "goarch": runtime.GOARCH},
	})
	build.Set(1)
	start := prometheus.NewGaugeFunc(prometheus.GaugeOpts{Namespace: ns, Name: "start_time_seconds", Help: "When the panel started."},
		func() float64 { return float64(started.Unix()) })
	Registry.MustRegister(build, start)
}

// Handler serves the registry, asking for the token when one is configured.
func Handler(token string) http.Handler {
	h := promhttp.HandlerFor(Registry, promhttp.HandlerOpts{EnableOpenMetrics: true, Timeout: 20 * time.Second})
	if token == "" {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Result names an outcome for a counter label from an error.
func Result(err error) string {
	if err != nil {
		return "error"
	}
	return "ok"
}
