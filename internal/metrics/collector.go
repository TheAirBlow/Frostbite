package metrics

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"frostbite/internal/link"
)

// Live is what the hub knows right now, which the database does not.
type Live struct {
	Daemons     map[int64]DaemonLive
	OnlineUsers map[int64]int // user id -> distinct addresses
}

// DaemonLive is one connected daemon.
type DaemonLive struct {
	Since     time.Time
	Metrics   *link.Metrics
	MetricsAt time.Time
	Certs     []link.CertStatus
	Users     int // distinct users connected through it
	IPs       int // distinct addresses connected to it
}

// Source is implemented by the hub.
type Source interface {
	LiveState() Live
}

// Options configure a Collector.
type Options struct {
	Pool        *pgxpool.Pool
	Live        Source
	DataDir     string
	PerUser     bool
	NotifyQueue func() int
	// CacheFor is how long database results are reused between scrapes.
	CacheFor time.Duration
}

// Collector turns the database and the hub into metrics when Prometheus scrapes.
type Collector struct {
	opt Options

	mu     sync.Mutex
	groups []*group
	// kept from the last good refresh, the live metrics need them to label what the hub reports
	daemons map[int64]daemonLabels
	users   map[int64]string
}

// group is a set of metrics that come from one place and are refreshed together.
type group struct {
	name    string
	run     func(ctx context.Context, c *Collector, emit func(prometheus.Metric)) error
	at      time.Time
	metrics []prometheus.Metric
}

// NewCollector registers a collector on Registry.
func NewCollector(opt Options) *Collector {
	if opt.CacheFor <= 0 {
		opt.CacheFor = 10 * time.Second
	}
	c := &Collector{opt: opt, daemons: map[int64]daemonLabels{}, users: map[int64]string{}}
	c.groups = []*group{
		{name: "users", run: collectUsers},
		{name: "nodes", run: collectNodes},
		{name: "daemons", run: collectDaemons},
		{name: "config", run: collectConfig},
		{name: "admins", run: collectAdmins},
		{name: "audit", run: collectAudit},
		{name: "postgres", run: collectPostgres},
		{name: "backups", run: collectBackups},
	}
	if opt.PerUser {
		c.groups = append(c.groups, &group{name: "user_series", run: collectUserSeries})
	}
	Registry.MustRegister(c)
	return c
}

// Describe sends nothing, which makes this an unchecked collector: label sets are not known ahead of time.
func (c *Collector) Describe(chan<- *prometheus.Desc) {}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, g := range c.groups {
		if time.Since(g.at) >= c.opt.CacheFor {
			c.refresh(ctx, g)
		}
		for _, m := range g.metrics {
			ch <- m
		}
	}
	c.collectPool(ch)
	c.collectLive(ch)
	if c.opt.NotifyQueue != nil {
		ch <- gv("notify_queue_length", "Events waiting to be delivered.", float64(c.opt.NotifyQueue()))
	}
}

// refresh reruns one group. A failure keeps what the group reported before and is counted.
func (c *Collector) refresh(ctx context.Context, g *group) {
	start := time.Now()
	var fresh []prometheus.Metric
	err := g.run(ctx, c, func(m prometheus.Metric) { fresh = append(fresh, m) })
	g.at = time.Now()
	collectSeconds.WithLabelValues(g.name).Set(time.Since(start).Seconds())
	if err != nil {
		collectErrors.WithLabelValues(g.name).Inc()
		slog.Warn("metrics: refreshing a group failed", "group", g.name, "err", err)
		return
	}
	collectLast.WithLabelValues(g.name).SetToCurrentTime()
	g.metrics = fresh
}

// metric helpers

var descs sync.Map // name -> *prometheus.Desc, keyed by name+labels

func desc(name, help string, labels []string) *prometheus.Desc {
	key := name + "|" + strings.Join(labels, ",")
	if d, ok := descs.Load(key); ok {
		return d.(*prometheus.Desc)
	}
	d := prometheus.NewDesc(prometheus.BuildFQName(ns, "", name), help, labels, nil)
	descs.Store(key, d)
	return d
}

func mk(t prometheus.ValueType, name, help string, v float64, labelNames []string, values []string) prometheus.Metric {
	return prometheus.MustNewConstMetric(desc(name, help, labelNames), t, v, values...)
}

// gv is a gauge without labels.
func gv(name, help string, v float64) prometheus.Metric {
	return mk(prometheus.GaugeValue, name, help, v, nil, nil)
}

// emitter builds metrics for one family of labels.
type emitter struct {
	emit   func(prometheus.Metric)
	labels []string
}

func (e emitter) gauge(name, help string, v float64, values ...string) {
	e.emit(mk(prometheus.GaugeValue, name, help, v, e.labels, values))
}

func (e emitter) counter(name, help string, v float64, values ...string) {
	e.emit(mk(prometheus.CounterValue, name, help, v, e.labels, values))
}

func with(emit func(prometheus.Metric), labels ...string) emitter { return emitter{emit, labels} }

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func ts(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// labels shared by everything about one daemon
type daemonLabels struct {
	ID       int64
	Name     string
	NodeID   int64
	Node     string
	Kind     string
	Hostname string
}

var daemonLabelNames = []string{"daemon_id", "daemon", "node_id", "node", "kind"}

func (d daemonLabels) values() []string {
	return []string{itoa(d.ID), d.Name, itoa(d.NodeID), d.Node, d.Kind}
}

// collectPool reports the connection pool the panel itself uses.
func (c *Collector) collectPool(ch chan<- prometheus.Metric) {
	if c.opt.Pool == nil {
		return
	}
	s := c.opt.Pool.Stat()
	ch <- mk(prometheus.GaugeValue, "db_pool_connections", "Connections in the pool by state.", float64(s.AcquiredConns()), []string{"state"}, []string{"acquired"})
	ch <- mk(prometheus.GaugeValue, "db_pool_connections", "Connections in the pool by state.", float64(s.IdleConns()), []string{"state"}, []string{"idle"})
	ch <- mk(prometheus.GaugeValue, "db_pool_connections", "Connections in the pool by state.", float64(s.ConstructingConns()), []string{"state"}, []string{"constructing"})
	ch <- mk(prometheus.GaugeValue, "db_pool_connections", "Connections in the pool by state.", float64(s.TotalConns()), []string{"state"}, []string{"total"})
	ch <- gv("db_pool_max_connections", "Most connections the pool may open.", float64(s.MaxConns()))
	ch <- mk(prometheus.CounterValue, "db_pool_acquires_total", "Times a connection was taken from the pool.", float64(s.AcquireCount()), nil, nil)
	ch <- mk(prometheus.CounterValue, "db_pool_acquire_seconds_total", "Time spent waiting to take a connection.", s.AcquireDuration().Seconds(), nil, nil)
	ch <- mk(prometheus.CounterValue, "db_pool_empty_acquires_total", "Acquires that had to wait because no connection was idle.", float64(s.EmptyAcquireCount()), nil, nil)
	ch <- mk(prometheus.CounterValue, "db_pool_canceled_acquires_total", "Acquires abandoned before a connection arrived.", float64(s.CanceledAcquireCount()), nil, nil)
	ch <- mk(prometheus.CounterValue, "db_pool_new_connections_total", "Connections opened over the pool's life.", float64(s.NewConnsCount()), nil, nil)
	ch <- mk(prometheus.CounterValue, "db_pool_destroyed_connections_total", "Connections closed by the pool, by reason.", float64(s.MaxLifetimeDestroyCount()), []string{"reason"}, []string{"max_lifetime"})
	ch <- mk(prometheus.CounterValue, "db_pool_destroyed_connections_total", "Connections closed by the pool, by reason.", float64(s.MaxIdleDestroyCount()), []string{"reason"}, []string{"max_idle"})
}

// collectLive reports what the hub holds in memory.
func (c *Collector) collectLive(ch chan<- prometheus.Metric) {
	if c.opt.Live == nil {
		return
	}
	live := c.opt.Live.LiveState()
	ch <- gv("online_users", "Users with at least one live connection right now.", float64(len(live.OnlineUsers)))
	ips := 0
	for _, n := range live.OnlineUsers {
		ips += n
	}
	ch <- gv("online_user_addresses", "Distinct source addresses summed over online users.", float64(ips))
	ch <- gv("daemons_connected", "Daemons with an open link.", float64(len(live.Daemons)))

	emit := func(m prometheus.Metric) { ch <- m }
	d := with(emit, daemonLabelNames...)
	known := map[int64]bool{}
	for id, dl := range live.Daemons {
		l, ok := c.daemons[id]
		if !ok {
			continue
		}
		known[id] = true
		v := l.values()
		d.gauge("daemon_up", "1 while the daemon has an open link to the panel.", 1, v...)
		d.gauge("daemon_connected_since_timestamp_seconds", "When the current link was opened.", ts(dl.Since), v...)
		d.gauge("daemon_online_users", "Distinct users connected through the daemon.", float64(dl.Users), v...)
		d.gauge("daemon_online_addresses", "Distinct source addresses connected to the daemon.", float64(dl.IPs), v...)
		for _, cert := range dl.Certs {
			cv := append(append([]string{}, v...), cert.Domain)
			e := with(emit, append(append([]string{}, daemonLabelNames...), "domain")...)
			e.gauge("daemon_cert_ok", "1 when automatic issuance for the domain works.", b2f(cert.OK), cv...)
			e.gauge("daemon_cert_placeholder", "1 while a self signed stand-in serves instead of the real certificate.", b2f(cert.Placeholder), cv...)
			e.gauge("daemon_cert_expiry_timestamp_seconds", "When the certificate expires.", ts(cert.Expires), cv...)
		}
		if m := dl.Metrics; m != nil {
			emitHost(d, v, m, dl.MetricsAt)
		}
	}
	for id, l := range c.daemons {
		if !known[id] {
			d.gauge("daemon_up", "1 while the daemon has an open link to the panel.", 0, l.values()...)
		}
	}

	if c.opt.PerUser {
		e := with(emit, "user")
		for id, n := range live.OnlineUsers {
			if name, ok := c.users[id]; ok {
				e.gauge("user_online_addresses", "Distinct source addresses a user is connected from right now.", float64(n), name)
			}
		}
	}
}

// emitHost turns a daemon's health sample into series.
func emitHost(d emitter, v []string, m *link.Metrics, at time.Time) {
	d.gauge("host_sample_age_seconds", "Seconds since the daemon last reported its health.", time.Since(at).Seconds(), v...)
	d.gauge("host_cpu_ratio", "CPU busy share of the host, 0 to 1.", m.CPU/100, v...)
	d.gauge("host_load1", "One minute load average.", m.Load1, v...)
	d.gauge("host_load5", "Five minute load average.", m.Load5, v...)
	d.gauge("host_load15", "Fifteen minute load average.", m.Load15, v...)
	d.gauge("host_memory_used_bytes", "Memory in use, not counting reclaimable cache.", float64(m.MemUsed), v...)
	d.gauge("host_memory_total_bytes", "Installed memory.", float64(m.MemTotal), v...)
	d.gauge("host_swap_used_bytes", "Swap in use.", float64(m.SwapUsed), v...)
	d.gauge("host_swap_total_bytes", "Swap available.", float64(m.SwapTotal), v...)
	d.gauge("host_disk_used_bytes", "Space used on the root filesystem.", float64(m.DiskUsed), v...)
	d.gauge("host_disk_total_bytes", "Size of the root filesystem.", float64(m.DiskTotal), v...)
	d.gauge("host_disk_read_bytes_per_second", "Disk read throughput.", float64(m.DiskRead), v...)
	d.gauge("host_disk_write_bytes_per_second", "Disk write throughput.", float64(m.DiskWrite), v...)
	d.gauge("host_network_up_bytes_per_second", "Bytes sent per second over every non loopback interface.", float64(m.NetUp), v...)
	d.gauge("host_network_down_bytes_per_second", "Bytes received per second over every non loopback interface.", float64(m.NetDown), v...)
	d.gauge("host_network_up_packets_per_second", "Packets sent per second.", float64(m.NetUpPackets), v...)
	d.gauge("host_network_down_packets_per_second", "Packets received per second.", float64(m.NetDownPackets), v...)
	d.gauge("host_network_errors_per_second", "Interface errors and drops per second.", float64(m.NetErrors), v...)
	d.gauge("host_tcp_connections", "Established TCP connections.", float64(m.TCPEstablished), v...)
	d.gauge("host_tcp_sockets_in_use", "TCP sockets in use.", float64(m.TCPInUse), v...)
	d.gauge("host_tcp_time_wait", "TCP sockets in TIME_WAIT.", float64(m.TCPTimeWait), v...)
	d.gauge("host_udp_sockets_in_use", "UDP sockets in use.", float64(m.UDPInUse), v...)
	d.gauge("host_open_files", "File descriptors allocated system wide.", float64(m.OpenFiles), v...)
	d.gauge("host_max_open_files", "System wide file descriptor limit.", float64(m.MaxOpenFiles), v...)
	d.gauge("host_processes", "Processes on the host.", float64(m.Processes), v...)
	d.gauge("host_uptime_seconds", "Host uptime.", float64(m.Uptime), v...)
	d.gauge("agent_goroutines", "Goroutines in the daemon.", float64(m.AgentGoroutines), v...)
	d.gauge("agent_heap_bytes", "Heap in use by the daemon.", float64(m.AgentHeap), v...)
	d.gauge("agent_uptime_seconds", "Time since the daemon process started.", float64(m.AgentUptime), v...)
}

// settingJSON reads one settings row.
func settingJSON(ctx context.Context, pool *pgxpool.Pool, key string, v any) bool {
	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, key).Scan(&raw); err != nil {
		return false
	}
	return json.Unmarshal(raw, v) == nil
}

// collectBackups looks at the files the scheduler keeps.
func collectBackups(_ context.Context, c *Collector, emit func(prometheus.Metric)) error {
	entries, err := os.ReadDir(filepath.Join(c.opt.DataDir, "backups"))
	if os.IsNotExist(err) {
		entries, err = nil, nil
	}
	if err != nil {
		return err
	}
	type f struct {
		at   time.Time
		size int64
	}
	var files []f
	var total int64
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json.gz") {
			continue
		}
		if info, err := e.Info(); err == nil {
			files = append(files, f{info.ModTime(), info.Size()})
			total += info.Size()
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].at.After(files[j].at) })
	emit(gv("backup_files", "Backup files kept on disk.", float64(len(files))))
	emit(gv("backup_files_bytes", "Disk space the backup files take.", float64(total)))
	if len(files) > 0 {
		emit(gv("backup_latest_timestamp_seconds", "When the newest backup file was written.", ts(files[0].at)))
		emit(gv("backup_latest_bytes", "Size of the newest backup file.", float64(files[0].size)))
		emit(gv("backup_oldest_timestamp_seconds", "When the oldest backup file was written.", ts(files[len(files)-1].at)))
	}
	var sc struct {
		Enabled       bool `json:"enabled"`
		IntervalHours int  `json:"interval_hours"`
		Keep          int  `json:"keep"`
		History       bool `json:"history"`
	}
	sc.Enabled, sc.IntervalHours, sc.Keep = true, 24, 14
	settingJSON(context.Background(), c.opt.Pool, "backup", &sc)
	emit(gv("backup_schedule_enabled", "1 when scheduled backups are on.", b2f(sc.Enabled)))
	emit(gv("backup_schedule_interval_seconds", "Time between scheduled backups.", float64(sc.IntervalHours)*3600))
	emit(gv("backup_schedule_keep", "Backups the schedule keeps.", float64(sc.Keep)))
	emit(gv("backup_schedule_includes_history", "1 when scheduled backups include hourly traffic rows.", b2f(sc.History)))
	return nil
}
