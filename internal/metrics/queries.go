package metrics

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"frostbite/internal/link"
)

// queryInts runs a query that returns one row of n bigint columns.
func queryInts(ctx context.Context, pool *pgxpool.Pool, n int, sql string) ([]int64, error) {
	vals := make([]int64, n)
	ptrs := make([]any, n)
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	err := pool.QueryRow(ctx, sql).Scan(ptrs...)
	return vals, err
}

var userStatuses = []string{"active", "on_hold", "limited", "expired", "disabled"}

// collectUsers reports what the users table says in aggregate.
func collectUsers(ctx context.Context, c *Collector, emit func(prometheus.Metric)) error {
	pool := c.opt.Pool

	rows, err := pool.Query(ctx, `SELECT status, count(*), COALESCE(sum(traffic_used), 0)::float8, COALESCE(sum(traffic_lifetime), 0)::float8, COALESCE(sum(traffic_limit), 0)::float8 FROM users GROUP BY status`)
	if err != nil {
		return err
	}
	type agg struct{ n, used, life, limit float64 }
	byStatus := map[string]agg{}
	for rows.Next() {
		var s string
		var a agg
		if err := rows.Scan(&s, &a.n, &a.used, &a.life, &a.limit); err != nil {
			rows.Close()
			return err
		}
		byStatus[s] = a
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	st := with(emit, "status")
	var total, used, life float64
	for _, s := range userStatuses {
		a := byStatus[s]
		st.gauge("users", "Users by status.", a.n, s)
		st.gauge("users_traffic_used_bytes", "Traffic used in the current period, by user status.", a.used, s)
		st.gauge("users_traffic_limit_bytes", "Traffic limits handed out, by user status. Unlimited users add nothing.", a.limit, s)
		total += a.n
		used += a.used
		life += a.life
	}
	emit(gv("users_count", "Users of any status.", total))
	emit(gv("users_traffic_used_all_bytes", "Traffic used in the current period, over all users.", used))
	emit(mk(prometheus.CounterValue, "users_traffic_lifetime_bytes_total", "Traffic ever booked against users. Falls only when users are deleted or a backup is restored.", life, nil, nil))

	v, err := queryInts(ctx, pool, 27, `
SELECT
 count(*) FILTER (WHERE blocked_until > now()),
 count(*) FILTER (WHERE online_at > now() - interval '3 minutes'),
 count(*) FILTER (WHERE online_at > now() - interval '1 hour'),
 count(*) FILTER (WHERE online_at > now() - interval '24 hours'),
 count(*) FILTER (WHERE online_at > now() - interval '7 days'),
 count(*) FILTER (WHERE online_at IS NULL),
 count(*) FILTER (WHERE expire_at IS NULL),
 count(*) FILTER (WHERE expire_at > now() AND expire_at <= now() + interval '1 day'),
 count(*) FILTER (WHERE expire_at > now() AND expire_at <= now() + interval '3 days'),
 count(*) FILTER (WHERE expire_at > now() AND expire_at <= now() + interval '7 days'),
 count(*) FILTER (WHERE expire_at > now() AND expire_at <= now() + interval '30 days'),
 count(*) FILTER (WHERE traffic_limit = 0),
 count(*) FILTER (WHERE telegram_id IS NOT NULL),
 count(*) FILTER (WHERE email <> ''),
 count(*) FILTER (WHERE sub_last_at > now() - interval '5 minutes'),
 count(*) FILTER (WHERE sub_last_at > now() - interval '1 hour'),
 count(*) FILTER (WHERE sub_last_at > now() - interval '24 hours'),
 count(*) FILTER (WHERE sub_last_at > now() - interval '7 days'),
 count(*) FILTER (WHERE sub_last_at IS NULL),
 count(*) FILTER (WHERE device_limit > 0),
 count(*) FILTER (WHERE ip_limit > 0),
 count(*) FILTER (WHERE created_at > now() - interval '24 hours'),
 count(*) FILTER (WHERE created_at > now() - interval '7 days'),
 count(*) FILTER (WHERE created_at > now() - interval '30 days'),
 count(*) FILTER (WHERE traffic_limit > 0 AND traffic_used >= traffic_limit),
 count(*) FILTER (WHERE plan_id IS NOT NULL),
 count(*) FILTER (WHERE owner_id IS NOT NULL)
FROM users`)
	if err != nil {
		return err
	}
	emit(gv("users_blocked", "Users cut off for breaking their address limit.", float64(v[0])))
	w := with(emit, "within")
	w.gauge("users_seen", "Users that carried traffic within the window.", float64(v[1]), "3m")
	w.gauge("users_seen", "Users that carried traffic within the window.", float64(v[2]), "1h")
	w.gauge("users_seen", "Users that carried traffic within the window.", float64(v[3]), "24h")
	w.gauge("users_seen", "Users that carried traffic within the window.", float64(v[4]), "7d")
	emit(gv("users_never_seen", "Users that never carried traffic.", float64(v[5])))
	emit(gv("users_without_expiry", "Users that never expire.", float64(v[6])))
	w.gauge("users_expiring", "Users whose subscription ends within the window.", float64(v[7]), "1d")
	w.gauge("users_expiring", "Users whose subscription ends within the window.", float64(v[8]), "3d")
	w.gauge("users_expiring", "Users whose subscription ends within the window.", float64(v[9]), "7d")
	w.gauge("users_expiring", "Users whose subscription ends within the window.", float64(v[10]), "30d")
	emit(gv("users_unlimited_traffic", "Users without a traffic limit.", float64(v[11])))
	emit(gv("users_with_telegram", "Users who linked a Telegram account.", float64(v[12])))
	emit(gv("users_with_email", "Users with an email address.", float64(v[13])))
	w.gauge("users_subscription_fetched", "Users whose client fetched the subscription within the window.", float64(v[14]), "5m")
	w.gauge("users_subscription_fetched", "Users whose client fetched the subscription within the window.", float64(v[15]), "1h")
	w.gauge("users_subscription_fetched", "Users whose client fetched the subscription within the window.", float64(v[16]), "24h")
	w.gauge("users_subscription_fetched", "Users whose client fetched the subscription within the window.", float64(v[17]), "7d")
	emit(gv("users_subscription_never_fetched", "Users whose client never fetched the subscription.", float64(v[18])))
	emit(gv("users_with_device_limit", "Users with a device limit.", float64(v[19])))
	emit(gv("users_with_ip_limit", "Users with an address limit.", float64(v[20])))
	w.gauge("users_created", "Users created within the window.", float64(v[21]), "24h")
	w.gauge("users_created", "Users created within the window.", float64(v[22]), "7d")
	w.gauge("users_created", "Users created within the window.", float64(v[23]), "30d")
	emit(gv("users_over_limit", "Users at or over their traffic limit, whatever their status says.", float64(v[24])))
	emit(gv("users_with_plan", "Users created from a plan.", float64(v[25])))
	emit(gv("users_with_owner", "Users that belong to an administrator or reseller.", float64(v[26])))

	// how much of their limit users have used
	ranges := []string{"<10%", "10-50%", "50-80%", "80-95%", "95-100%", ">=100%"}
	usage := map[string]float64{}
	if err := scanPairs(ctx, pool, `
SELECT CASE WHEN r < .1 THEN '<10%' WHEN r < .5 THEN '10-50%' WHEN r < .8 THEN '50-80%' WHEN r < .95 THEN '80-95%' WHEN r < 1 THEN '95-100%' ELSE '>=100%' END, count(*)::float8
FROM (SELECT traffic_used::float8 / traffic_limit AS r FROM users WHERE traffic_limit > 0) t GROUP BY 1`, usage); err != nil {
		return err
	}
	r := with(emit, "usage")
	for _, name := range ranges {
		r.gauge("users_by_usage", "Users with a traffic limit, by how much of it they used.", usage[name], name)
	}

	reset := map[string]float64{}
	if err := scanPairs(ctx, pool, `SELECT reset_strategy, count(*)::float8 FROM users GROUP BY 1`, reset); err != nil {
		return err
	}
	rs := with(emit, "strategy")
	for _, s := range []string{"none", "day", "week", "month", "year"} {
		rs.gauge("users_by_reset_strategy", "Users by how their traffic resets.", reset[s], s)
	}

	plans := map[string]float64{}
	if err := scanPairs(ctx, pool, `SELECT COALESCE(p.name, '(none)'), count(*)::float8 FROM users u LEFT JOIN plans p ON p.id = u.plan_id GROUP BY 1`, plans); err != nil {
		return err
	}
	pl := with(emit, "plan")
	for name, n := range plans {
		pl.gauge("users_by_plan", "Users by plan.", n, name)
	}

	tags := map[string]float64{}
	if err := scanPairs(ctx, pool, `SELECT t, count(*)::float8 FROM users, unnest(tags) t GROUP BY 1 ORDER BY 2 DESC LIMIT 100`, tags); err != nil {
		return err
	}
	tg := with(emit, "tag")
	for name, n := range tags {
		tg.gauge("users_by_tag", "Users by tag, the 100 most used.", n, name)
	}

	squads := map[string]float64{}
	if err := scanPairs(ctx, pool, `SELECT s.name, count(us.user_id)::float8 FROM squads s LEFT JOIN user_squads us ON us.squad_id = s.id GROUP BY s.name`, squads); err != nil {
		return err
	}
	sq := with(emit, "squad")
	for name, n := range squads {
		sq.gauge("squad_users", "Users in each squad.", n, name)
	}

	owners, err := pool.Query(ctx, `
SELECT COALESCE(a.username, '(none)'), count(*)::float8, COALESCE(sum(u.traffic_used), 0)::float8, COALESCE(sum(u.traffic_lifetime), 0)::float8
FROM users u LEFT JOIN admins a ON a.id = u.owner_id GROUP BY 1`)
	if err != nil {
		return err
	}
	ow := with(emit, "owner")
	for owners.Next() {
		var name string
		var n, used, life float64
		if err := owners.Scan(&name, &n, &used, &life); err != nil {
			owners.Close()
			return err
		}
		ow.gauge("owner_users", "Users by the administrator who owns them.", n, name)
		ow.gauge("owner_users_traffic_used_bytes", "Traffic used this period by an administrator's users.", used, name)
		ow.counter("owner_users_traffic_lifetime_bytes_total", "Traffic ever booked against an administrator's users.", life, name)
	}
	owners.Close()
	if err := owners.Err(); err != nil {
		return err
	}

	// devices
	dv, err := queryInts(ctx, pool, 4, `SELECT count(*), count(DISTINCT user_id), count(*) FILTER (WHERE last_seen > now() - interval '24 hours'), count(*) FILTER (WHERE last_seen > now() - interval '7 days') FROM user_devices`)
	if err != nil {
		return err
	}
	emit(gv("devices", "Devices registered by subscription clients.", float64(dv[0])))
	emit(gv("devices_users", "Users with at least one registered device.", float64(dv[1])))
	w.gauge("devices_active", "Devices that fetched a subscription within the window.", float64(dv[2]), "24h")
	w.gauge("devices_active", "Devices that fetched a subscription within the window.", float64(dv[3]), "7d")
	plat := map[string]float64{}
	if err := scanPairs(ctx, pool, `SELECT COALESCE(NULLIF(lower(platform), ''), 'unknown'), count(*)::float8 FROM user_devices GROUP BY 1`, plat); err != nil {
		return err
	}
	pf := with(emit, "platform")
	for name, n := range plat {
		pf.gauge("devices_by_platform", "Registered devices by platform.", n, name)
	}

	// which client apps people use, from the last user agent each of them fetched with
	uas := map[string]float64{}
	if err := scanPairs(ctx, pool, `SELECT sub_last_ua, count(*)::float8 FROM users WHERE sub_last_ua <> '' GROUP BY 1`, uas); err != nil {
		return err
	}
	clients := map[string]float64{}
	for ua, n := range uas {
		clients[clientFamily(ua)] += n
	}
	cl := with(emit, "client")
	for name, n := range topN(clients, 25) {
		cl.gauge("users_by_client", "Users by the client app of their last subscription fetch.", n, name)
	}
	return nil
}

// clientFamily reduces a user agent to the app name.
func clientFamily(ua string) string {
	f := strings.FieldsFunc(strings.ToLower(ua), func(r rune) bool { return r == '/' || r == ' ' || r == ';' || r == '(' })
	if len(f) == 0 {
		return "unknown"
	}
	name := f[0]
	if len(name) > 32 {
		name = name[:32]
	}
	return name
}

// topN keeps the n biggest entries and folds the rest into "other".
func topN(m map[string]float64, n int) map[string]float64 {
	if len(m) <= n {
		return m
	}
	type kv struct {
		k string
		v float64
	}
	list := make([]kv, 0, len(m))
	for k, v := range m {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v })
	out := map[string]float64{}
	for i, e := range list {
		if i < n-1 {
			out[e.k] = e.v
		} else {
			out["other"] += e.v
		}
	}
	return out
}

// scanPairs fills m from a query of (text, float) rows.
func scanPairs(ctx context.Context, pool *pgxpool.Pool, sql string, m map[string]float64) error {
	rows, err := pool.Query(ctx, sql)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var v float64
		if err := rows.Scan(&k, &v); err != nil {
			return err
		}
		m[k] += v
	}
	return rows.Err()
}

// collectUserSeries adds series for each user, which is why it can be switched off.
func collectUserSeries(ctx context.Context, c *Collector, emit func(prometheus.Metric)) error {
	rows, err := c.opt.Pool.Query(ctx, `
SELECT u.id, u.username, u.status, COALESCE(p.name, ''), COALESCE(a.username, ''),
       u.traffic_used, u.traffic_limit, u.traffic_lifetime, u.expire_at, u.online_at, u.sub_last_at, u.blocked_until,
       u.ip_limit, u.device_limit, u.created_at, (SELECT count(*) FROM user_devices d WHERE d.user_id = u.id)
FROM users u LEFT JOIN plans p ON p.id = u.plan_id LEFT JOIN admins a ON a.id = u.owner_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	info := with(emit, "user", "status", "plan", "owner")
	one := with(emit, "user")
	names := map[int64]string{}
	for rows.Next() {
		var (
			id                           int64
			name, status, plan, owner    string
			used, limit, life            int64
			expire, online, sub, blocked *time.Time
			ipLimit, devLimit            int32
			created                      time.Time
			devices                      int64
		)
		if err := rows.Scan(&id, &name, &status, &plan, &owner, &used, &limit, &life, &expire, &online, &sub, &blocked, &ipLimit, &devLimit, &created, &devices); err != nil {
			return err
		}
		names[id] = name
		info.gauge("user_info", "Always 1, carries a user's status, plan and owner.", 1, name, status, plan, owner)
		one.gauge("user_traffic_used_bytes", "Traffic a user used in the current period.", float64(used), name)
		one.gauge("user_traffic_limit_bytes", "A user's traffic limit, 0 for unlimited.", float64(limit), name)
		one.counter("user_traffic_lifetime_bytes_total", "Traffic ever booked against a user.", float64(life), name)
		one.gauge("user_ip_limit", "How many addresses a user may connect from, 0 for no limit.", float64(ipLimit), name)
		one.gauge("user_device_limit", "How many devices a user may register, 0 for no limit.", float64(devLimit), name)
		one.gauge("user_devices", "Devices a user registered.", float64(devices), name)
		one.gauge("user_created_timestamp_seconds", "When a user was created.", ts(created), name)
		if expire != nil {
			one.gauge("user_expire_timestamp_seconds", "When a user's subscription ends.", ts(*expire), name)
		}
		if online != nil {
			one.gauge("user_last_online_timestamp_seconds", "When a user last carried traffic.", ts(*online), name)
		}
		if sub != nil {
			one.gauge("user_last_subscription_fetch_timestamp_seconds", "When a client of the user last fetched the subscription.", ts(*sub), name)
		}
		if blocked != nil && blocked.After(time.Now()) {
			one.gauge("user_blocked_until_timestamp_seconds", "Until when a user is cut off for breaking the address limit.", ts(*blocked), name)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	c.users = names
	return nil
}

// collectNodes reports nodes and the traffic recorded against them.
func collectNodes(ctx context.Context, c *Collector, emit func(prometheus.Metric)) error {
	rows, err := c.opt.Pool.Query(ctx, `
SELECT n.id, n.name, n.address, n.country, array_to_string(n.tags, ','), n.traffic_multiplier, n.traffic_limit, n.traffic_used,
       n.enabled, n.created_at, (SELECT count(*) FROM daemons d WHERE d.node_id = n.id)
FROM nodes n`)
	if err != nil {
		return err
	}
	type node struct {
		id   int64
		name string
	}
	var nodes []node
	info := with(emit, "node_id", "node", "address", "country", "tags")
	one := with(emit, "node_id", "node")
	for rows.Next() {
		var (
			id                       int64
			name, addr, country, tag string
			mult                     float64
			limit, used, daemons     int64
			enabled                  bool
			created                  time.Time
		)
		if err := rows.Scan(&id, &name, &addr, &country, &tag, &mult, &limit, &used, &enabled, &created, &daemons); err != nil {
			rows.Close()
			return err
		}
		nodes = append(nodes, node{id, name})
		i := itoa(id)
		info.gauge("node_info", "Always 1, carries a node's address, country and tags.", 1, i, name, addr, country, tag)
		one.gauge("node_enabled", "1 when the node is enabled.", b2f(enabled), i, name)
		one.gauge("node_traffic_multiplier", "Factor applied to the node's traffic before it counts against users.", mult, i, name)
		one.gauge("node_traffic_limit_bytes", "Traffic the node may carry, 0 for no limit.", float64(limit), i, name)
		one.counter("node_traffic_used_bytes_total", "Raw traffic the node carried, before the multiplier.", float64(used), i, name)
		one.gauge("node_created_timestamp_seconds", "When the node was added.", ts(created), i, name)
		one.gauge("node_daemons", "Daemons on the node.", float64(daemons), i, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	names := map[int64]string{}
	for _, n := range nodes {
		names[n.id] = n.name
	}

	// what the hourly table holds, which survives restarts and reaches back further than Prometheus may
	tr, err := c.opt.Pool.Query(ctx, `
SELECT node_id,
  COALESCE(sum(up), 0)::float8, COALESCE(sum(down), 0)::float8,
  COALESCE(sum(up) FILTER (WHERE hour >= now() - interval '1 hour'), 0)::float8, COALESCE(sum(down) FILTER (WHERE hour >= now() - interval '1 hour'), 0)::float8,
  COALESCE(sum(up) FILTER (WHERE hour >= now() - interval '24 hours'), 0)::float8, COALESCE(sum(down) FILTER (WHERE hour >= now() - interval '24 hours'), 0)::float8,
  COALESCE(sum(up) FILTER (WHERE hour >= now() - interval '7 days'), 0)::float8, COALESCE(sum(down) FILTER (WHERE hour >= now() - interval '7 days'), 0)::float8,
  COALESCE(sum(up) FILTER (WHERE hour >= now() - interval '30 days'), 0)::float8, COALESCE(sum(down) FILTER (WHERE hour >= now() - interval '30 days'), 0)::float8,
  count(DISTINCT user_id) FILTER (WHERE hour >= now() - interval '24 hours')::float8,
  count(DISTINCT user_id) FILTER (WHERE hour >= now() - interval '7 days')::float8
FROM traffic_hourly GROUP BY node_id`)
	if err != nil {
		return err
	}
	defer tr.Close()
	win := with(emit, "node_id", "node", "window", "direction")
	act := with(emit, "node_id", "node", "window")
	for tr.Next() {
		var id int64
		var v [12]float64
		var u24, u7 float64
		if err := tr.Scan(&id, &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7], &v[8], &v[9], &u24, &u7); err != nil {
			return err
		}
		name, ok := names[id]
		if !ok {
			continue
		}
		i := itoa(id)
		for k, w := range []string{"all", "1h", "24h", "7d", "30d"} {
			win.gauge("node_traffic_window_bytes", "Billed traffic recorded for the node in the window, split by direction. 'all' reaches back as far as hourly rows are kept.", v[k*2], i, name, w, "up")
			win.gauge("node_traffic_window_bytes", "Billed traffic recorded for the node in the window, split by direction. 'all' reaches back as far as hourly rows are kept.", v[k*2+1], i, name, w, "down")
		}
		act.gauge("node_active_users", "Users who carried traffic through the node in the window.", u24, i, name, "24h")
		act.gauge("node_active_users", "Users who carried traffic through the node in the window.", u7, i, name, "7d")
	}
	return tr.Err()
}

// collectDaemons reports daemons and their configuration inventory.
func collectDaemons(ctx context.Context, c *Collector, emit func(prometheus.Metric)) error {
	rows, err := c.opt.Pool.Query(ctx, `
SELECT d.id, d.node_id, n.name, d.kind, d.name, d.enabled, d.desired_rev, d.applied_rev, d.last_error, d.last_seen,
       d.core_version, d.agent_version, d.host_info, d.log_level, d.created_at,
       (SELECT count(*) FROM inbounds i WHERE i.daemon_id = d.id),
       (SELECT count(*) FROM inbounds i WHERE i.daemon_id = d.id AND i.enabled),
       (SELECT count(*) FROM outbounds o WHERE o.daemon_id = d.id),
       (SELECT count(*) FROM rules r WHERE r.daemon_id = d.id)
FROM daemons d JOIN nodes n ON n.id = d.node_id`)
	if err != nil {
		return err
	}
	defer rows.Close()

	found := map[int64]daemonLabels{}
	one := with(emit, daemonLabelNames...)
	info := with(emit, append(append([]string{}, daemonLabelNames...), "core_version", "agent_version", "hostname", "os", "arch", "kernel", "log_level")...)
	errs := with(emit, append(append([]string{}, daemonLabelNames...), "error")...)
	for rows.Next() {
		var (
			l                                         daemonLabels
			enabled                                   bool
			desired, applied                          int64
			lastErr, coreVer, agentVer, logLevel      string
			lastSeen                                  *time.Time
			hostRaw                                   []byte
			created                                   time.Time
			inbounds, enabledInbounds, outbounds, rls int64
		)
		if err := rows.Scan(&l.ID, &l.NodeID, &l.Node, &l.Kind, &l.Name, &enabled, &desired, &applied, &lastErr, &lastSeen,
			&coreVer, &agentVer, &hostRaw, &logLevel, &created, &inbounds, &enabledInbounds, &outbounds, &rls); err != nil {
			return err
		}
		var host link.HostInfo
		_ = json.Unmarshal(hostRaw, &host)
		found[l.ID] = l
		v := l.values()

		info.gauge("daemon_info", "Always 1, carries a daemon's versions and host.", 1, append(append([]string{}, v...), coreVer, agentVer, host.Hostname, host.OS, host.Arch, host.Kernel, logLevel)...)
		one.gauge("daemon_enabled", "1 when the daemon is enabled.", b2f(enabled), v...)
		one.gauge("daemon_desired_revision", "Revision of the spec the panel wants the daemon to run.", float64(desired), v...)
		one.gauge("daemon_applied_revision", "Revision of the spec the daemon last applied.", float64(applied), v...)
		one.gauge("daemon_in_sync", "1 when the daemon runs the revision the panel wants and reported no error.", b2f(applied == desired && lastErr == ""), v...)
		one.gauge("daemon_has_error", "1 when the daemon's last attempt to apply a spec failed.", b2f(lastErr != ""), v...)
		if lastErr != "" {
			errs.gauge("daemon_last_error_info", "Always 1 while the daemon's last apply failed, carries the error text.", 1, append(append([]string{}, v...), truncate(lastErr, 300))...)
		}
		if lastSeen != nil {
			one.gauge("daemon_last_seen_timestamp_seconds", "When the daemon was last heard from.", ts(*lastSeen), v...)
		}
		one.gauge("daemon_created_timestamp_seconds", "When the daemon was added.", ts(created), v...)
		one.gauge("daemon_inbounds", "Inbounds on the daemon.", float64(inbounds), v...)
		one.gauge("daemon_enabled_inbounds", "Enabled inbounds on the daemon.", float64(enabledInbounds), v...)
		one.gauge("daemon_outbounds", "Outbounds on the daemon.", float64(outbounds), v...)
		one.gauge("daemon_rules", "Routing rules that apply only to the daemon.", float64(rls), v...)
		one.gauge("daemon_host_cpus", "CPU cores the daemon's host reported when it connected.", float64(host.CPUs), v...)
		one.gauge("daemon_host_memory_installed_bytes", "Memory the daemon's host reported when it connected.", float64(host.MemTotal), v...)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	c.daemons = found

	kinds := map[string]float64{}
	for _, d := range found {
		kinds[d.Kind]++
	}
	k := with(emit, "kind")
	for kind, n := range kinds {
		k.gauge("daemons", "Daemons by kind.", n, kind)
	}
	emit(gv("daemons_count", "Daemons of any kind.", float64(len(found))))
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// collectConfig reports what has been set up.
func collectConfig(ctx context.Context, c *Collector, emit func(prometheus.Metric)) error {
	pool := c.opt.Pool

	rows, err := pool.Query(ctx, `
SELECT i.id, i.tag, i.remark, i.daemon_id, i.protocol, i.port, i.enabled, i.system,
       COALESCE(i.transport->>'type', ''), COALESCE(i.security->>'type', ''), i.edge_daemon_id IS NOT NULL,
       (SELECT count(*) FROM hosts h WHERE h.inbound_id = i.id),
       (SELECT count(*) FROM squad_inbounds s WHERE s.inbound_id = i.id)
FROM inbounds i`)
	if err != nil {
		return err
	}
	type roll struct{ protocol, transport, security, enabled, system, edge string }
	counts := map[roll]float64{}
	info := with(emit, "inbound_id", "tag", "remark", "daemon_id", "daemon", "node_id", "node", "protocol", "port", "transport", "security", "system", "behind_edge")
	one := with(emit, "inbound_id", "tag", "daemon_id", "daemon", "node_id", "node")
	for rows.Next() {
		var (
			id, daemonID, hosts, squads    int64
			tag, remark, protocol, tr, sec string
			port                           int32
			enabled, system, edge          bool
		)
		if err := rows.Scan(&id, &tag, &remark, &daemonID, &protocol, &port, &enabled, &system, &tr, &sec, &edge, &hosts, &squads); err != nil {
			rows.Close()
			return err
		}
		counts[roll{protocol, tr, sec, boolStr(enabled), boolStr(system), boolStr(edge)}]++
		d := c.daemons[daemonID]
		i, di, ni := itoa(id), itoa(daemonID), itoa(d.NodeID)
		info.gauge("inbound_info", "Always 1, carries an inbound's protocol, port and placement.", 1, i, tag, remark, di, d.Name, ni, d.Node, protocol, itoa(int64(port)), tr, sec, boolStr(system), boolStr(edge))
		one.gauge("inbound_enabled", "1 when the inbound is enabled.", b2f(enabled), i, tag, di, d.Name, ni, d.Node)
		one.gauge("inbound_hosts", "Hosts that advertise the inbound to clients.", float64(hosts), i, tag, di, d.Name, ni, d.Node)
		one.gauge("inbound_squads", "Squads that include the inbound.", float64(squads), i, tag, di, d.Name, ni, d.Node)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	rl := with(emit, "protocol", "transport", "security", "enabled", "system", "behind_edge")
	for r, n := range counts {
		rl.gauge("inbounds", "Inbounds by protocol, transport and security.", n, r.protocol, r.transport, r.security, r.enabled, r.system, r.edge)
	}

	// hosts, outbounds, rules and the like
	v, err := queryInts(ctx, pool, 12, `
SELECT (SELECT count(*) FROM hosts), (SELECT count(*) FROM hosts WHERE enabled), (SELECT count(*) FROM hosts WHERE bridge_inbound_id IS NOT NULL),
       (SELECT count(*) FROM rules), (SELECT count(*) FROM rules WHERE enabled), (SELECT count(*) FROM rules WHERE daemon_id IS NULL),
       (SELECT count(*) FROM squads), (SELECT count(*) FROM plans), (SELECT count(*) FROM sub_templates),
       (SELECT count(*) FROM sub_rules), (SELECT count(*) FROM sub_rules WHERE enabled), (SELECT count(*) FROM squad_inbounds)`)
	if err != nil {
		return err
	}
	for i, m := range []struct{ name, help string }{
		{"hosts", "Hosts that advertise inbounds."}, {"hosts_enabled", "Enabled hosts."}, {"hosts_bridged", "Hosts that reach their inbound through a relay or chain."},
		{"routing_rules", "Routing rules."}, {"routing_rules_enabled", "Enabled routing rules."}, {"routing_rules_global", "Routing rules that apply to every daemon."},
		{"squads", "Squads."}, {"plans", "Plans."}, {"subscription_templates", "Subscription templates."},
		{"subscription_rules", "Rules that pick a subscription format by user agent."}, {"subscription_rules_enabled", "Enabled subscription rules."}, {"squad_inbound_links", "Inbounds attached to squads, summed over squads."},
	} {
		emit(gv(m.name, m.help, float64(v[i])))
	}

	ob := map[string]float64{}
	if err := scanPairs(ctx, pool, `SELECT kind, count(*)::float8 FROM outbounds GROUP BY 1`, ob); err != nil {
		return err
	}
	ok := with(emit, "kind")
	for _, kind := range []string{"direct", "block", "proxy", "warp"} {
		ok.gauge("outbounds", "Outbounds by kind.", ob[kind], kind)
	}
	tf := map[string]float64{}
	if err := scanPairs(ctx, pool, `SELECT format, count(*)::float8 FROM sub_templates GROUP BY 1`, tf); err != nil {
		return err
	}
	for f, n := range tf {
		ok.gauge("subscription_templates_by_format", "Subscription templates by format.", n, f)
	}

	pr, err := pool.Query(ctx, `SELECT name, traffic_limit, duration_days, device_limit, ip_limit, start_on_first_use, cardinality(squad_ids) FROM plans`)
	if err != nil {
		return err
	}
	pl := with(emit, "plan")
	for pr.Next() {
		var name string
		var limit int64
		var days, dev, ip, squads int32
		var first bool
		if err := pr.Scan(&name, &limit, &days, &dev, &ip, &first, &squads); err != nil {
			pr.Close()
			return err
		}
		pl.gauge("plan_traffic_limit_bytes", "Traffic limit of a plan, 0 for unlimited.", float64(limit), name)
		pl.gauge("plan_duration_seconds", "Length of a plan, 0 for no end.", float64(days)*86400, name)
		pl.gauge("plan_device_limit", "Device limit of a plan.", float64(dev), name)
		pl.gauge("plan_ip_limit", "Address limit of a plan.", float64(ip), name)
		pl.gauge("plan_start_on_first_use", "1 when a plan's clock starts at first use.", b2f(first), name)
		pl.gauge("plan_squads", "Squads a plan grants.", float64(squads), name)
	}
	pr.Close()
	if err := pr.Err(); err != nil {
		return err
	}

	// notification settings, without their secrets
	var ns struct {
		Webhooks []struct {
			Enabled bool     `json:"enabled"`
			Events  []string `json:"events"`
		} `json:"webhooks"`
		Telegram struct {
			Enabled     bool    `json:"enabled"`
			AdminIDs    []int64 `json:"admin_ids"`
			NotifyUsers bool    `json:"notify_users"`
		} `json:"telegram"`
		ExpireDays   []int `json:"expire_days"`
		UsagePercent []int `json:"usage_percent"`
	}
	settingJSON(ctx, pool, "notifications", &ns)
	enabled := 0
	for _, w := range ns.Webhooks {
		if w.Enabled {
			enabled++
		}
	}
	emit(gv("notify_webhooks", "Webhooks configured.", float64(len(ns.Webhooks))))
	emit(gv("notify_webhooks_enabled", "Webhooks that are switched on.", float64(enabled)))
	emit(gv("notify_telegram_enabled", "1 when the Telegram bot is switched on.", b2f(ns.Telegram.Enabled)))
	emit(gv("notify_telegram_admins", "Telegram chats that receive admin alerts.", float64(len(ns.Telegram.AdminIDs))))
	emit(gv("notify_telegram_notify_users", "1 when users who linked Telegram are messaged.", b2f(ns.Telegram.NotifyUsers)))
	emit(gv("notify_expire_thresholds", "Days before expiry at which users are warned.", float64(len(ns.ExpireDays))))
	emit(gv("notify_usage_thresholds", "Usage percentages at which users are warned.", float64(len(ns.UsagePercent))))

	var warp struct {
		PrivateKey string `json:"private_key"`
		Type       string `json:"type"`
	}
	settingJSON(ctx, pool, "warp", &warp)
	wt := with(emit, "type")
	registered := warp.PrivateKey != ""
	emit(gv("warp_registered", "1 when a Cloudflare WARP account is registered.", b2f(registered)))
	if registered {
		wt.gauge("warp_account", "Always 1 for the registered WARP account, labelled with its type.", 1, warp.Type)
	}

	nl, err := pool.Query(ctx, `SELECT kind, count(*)::float8, extract(epoch FROM max(sent_at))::float8 FROM notification_log GROUP BY kind`)
	if err != nil {
		return err
	}
	defer nl.Close()
	for nl.Next() {
		var kind string
		var n, last float64
		if err := nl.Scan(&kind, &n, &last); err != nil {
			return err
		}
		ok.gauge("notification_log_entries", "Alerts remembered in the dedupe log (kept 90 days), by kind.", n, kind)
		ok.gauge("notification_log_last_timestamp_seconds", "When the newest alert of the kind went out.", last, kind)
	}
	return nl.Err()
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// collectAdmins reports administrators, resellers, sessions and API tokens.
func collectAdmins(ctx context.Context, c *Collector, emit func(prometheus.Metric)) error {
	pool := c.opt.Pool
	rows, err := pool.Query(ctx, `
SELECT a.username, a.role, a.enabled, a.user_quota, a.traffic_quota, a.created_at,
       (SELECT count(*) FROM users u WHERE u.owner_id = a.id),
       COALESCE((SELECT sum(traffic_limit) FROM users u WHERE u.owner_id = a.id), 0),
       COALESCE((SELECT sum(traffic_used) FROM users u WHERE u.owner_id = a.id), 0),
       (SELECT count(*) FROM sessions s WHERE s.admin_id = a.id AND s.expires_at > now()),
       (SELECT count(*) FROM api_tokens t WHERE t.admin_id = a.id),
       (SELECT max(last_used_at) FROM api_tokens t WHERE t.admin_id = a.id),
       (SELECT max(created_at) FROM sessions s WHERE s.admin_id = a.id)
FROM admins a`)
	if err != nil {
		return err
	}
	defer rows.Close()
	roles := map[[2]string]float64{}
	info := with(emit, "admin", "role", "enabled")
	one := with(emit, "admin")
	for rows.Next() {
		var (
			name, role             string
			enabled                bool
			userQuota              *int32
			trafficQuota           *int64
			created                time.Time
			users, allocated, used int64
			sessions, tokens       int64
			tokenUsed, lastSession *time.Time
		)
		if err := rows.Scan(&name, &role, &enabled, &userQuota, &trafficQuota, &created, &users, &allocated, &used, &sessions, &tokens, &tokenUsed, &lastSession); err != nil {
			return err
		}
		roles[[2]string{role, boolStr(enabled)}]++
		info.gauge("admin_info", "Always 1, carries an administrator's role.", 1, name, role, boolStr(enabled))
		one.gauge("admin_users", "Users an administrator owns.", float64(users), name)
		one.gauge("admin_traffic_allocated_bytes", "Traffic limits handed to the administrator's users.", float64(allocated), name)
		one.gauge("admin_traffic_used_bytes", "Traffic the administrator's users used this period.", float64(used), name)
		one.gauge("admin_sessions", "Live sign in sessions.", float64(sessions), name)
		one.gauge("admin_api_tokens", "API tokens.", float64(tokens), name)
		one.gauge("admin_created_timestamp_seconds", "When the account was created.", ts(created), name)
		if userQuota != nil {
			one.gauge("admin_user_quota", "How many users the administrator may own.", float64(*userQuota), name)
		}
		if trafficQuota != nil {
			one.gauge("admin_traffic_quota_bytes", "How much traffic the administrator may hand out.", float64(*trafficQuota), name)
		}
		if tokenUsed != nil {
			one.gauge("admin_api_token_last_used_timestamp_seconds", "When one of the administrator's tokens was last used.", ts(*tokenUsed), name)
		}
		if lastSession != nil {
			one.gauge("admin_last_session_timestamp_seconds", "When the administrator last signed in.", ts(*lastSession), name)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rl := with(emit, "role", "enabled")
	for _, role := range []string{"owner", "admin", "reseller"} {
		for _, en := range []string{"true", "false"} {
			rl.gauge("admins", "Administrator accounts by role.", roles[[2]string{role, en}], role, en)
		}
	}

	v, err := queryInts(ctx, pool, 5, `
SELECT (SELECT count(*) FROM sessions WHERE expires_at > now()), (SELECT count(*) FROM sessions WHERE expires_at <= now()),
       (SELECT count(*) FROM api_tokens), (SELECT count(*) FROM api_tokens WHERE last_used_at > now() - interval '24 hours'),
       (SELECT count(*) FROM api_tokens WHERE last_used_at IS NULL)`)
	if err != nil {
		return err
	}
	emit(gv("sessions_active", "Sign in sessions that have not expired.", float64(v[0])))
	emit(gv("sessions_expired_pending_cleanup", "Expired sessions waiting for the hourly cleanup.", float64(v[1])))
	emit(gv("api_tokens", "API tokens.", float64(v[2])))
	emit(gv("api_tokens_used_24h", "API tokens used in the last day.", float64(v[3])))
	emit(gv("api_tokens_never_used", "API tokens that were never used.", float64(v[4])))
	return nil
}

// collectAudit summarises the audit log.
func collectAudit(ctx context.Context, c *Collector, emit func(prometheus.Metric)) error {
	v, err := queryInts(ctx, c.opt.Pool, 3, `SELECT count(*), count(*) FILTER (WHERE created_at > now() - interval '24 hours'), COALESCE(extract(epoch FROM max(created_at))::bigint, 0) FROM audit_log`)
	if err != nil {
		return err
	}
	emit(gv("audit_log_entries", "Rows in the audit log.", float64(v[0])))
	emit(gv("audit_log_entries_24h", "Audit log rows from the last day.", float64(v[1])))
	if v[2] > 0 {
		emit(gv("audit_log_last_timestamp_seconds", "When the newest audit row was written.", float64(v[2])))
	}
	actions := map[string]float64{}
	if err := scanPairs(ctx, c.opt.Pool, `SELECT action, count(*)::float8 FROM audit_log WHERE created_at > now() - interval '24 hours' GROUP BY 1`, actions); err != nil {
		return err
	}
	a := with(emit, "action")
	for name, n := range actions {
		a.gauge("audit_log_actions_24h", "Audit rows from the last day, by action.", n, name)
	}
	return nil
}

// collectPostgres reports what the database server says about itself.
func collectPostgres(ctx context.Context, c *Collector, emit func(prometheus.Metric)) error {
	pool := c.opt.Pool

	var size, version, maxConn, schema int64
	var started float64
	if err := pool.QueryRow(ctx, `SELECT pg_database_size(current_database()), current_setting('server_version_num')::bigint, current_setting('max_connections')::bigint,
		extract(epoch FROM pg_postmaster_start_time())::float8, COALESCE((SELECT max(version_id) FROM goose_db_version), 0)`).Scan(&size, &version, &maxConn, &started, &schema); err != nil {
		return err
	}
	emit(gv("postgres_database_size_bytes", "Size of the panel's database.", float64(size)))
	emit(gv("postgres_server_version", "Server version as a number, 170002 is 17.2.", float64(version)))
	emit(gv("postgres_max_connections", "Connections the server accepts.", float64(maxConn)))
	emit(gv("postgres_start_time_seconds", "When the database server started.", started))
	emit(gv("db_schema_version", "Latest applied migration.", float64(schema)))

	var (
		backends, commit, rollback, read, hit, ret, fetched, ins, upd, del, conflicts, tempFiles, tempBytes, deadlocks int64
	)
	if err := pool.QueryRow(ctx, `SELECT numbackends, xact_commit, xact_rollback, blks_read, blks_hit, tup_returned, tup_fetched, tup_inserted, tup_updated, tup_deleted,
		conflicts, temp_files, temp_bytes, deadlocks FROM pg_stat_database WHERE datname = current_database()`).Scan(
		&backends, &commit, &rollback, &read, &hit, &ret, &fetched, &ins, &upd, &del, &conflicts, &tempFiles, &tempBytes, &deadlocks); err != nil {
		return err
	}
	cn := func(name, help string, v int64) { emit(mk(prometheus.CounterValue, name, help, float64(v), nil, nil)) }
	emit(gv("postgres_backends", "Connections to the panel's database.", float64(backends)))
	cn("postgres_transactions_committed_total", "Committed transactions.", commit)
	cn("postgres_transactions_rolled_back_total", "Rolled back transactions.", rollback)
	cn("postgres_blocks_read_total", "Disk blocks read.", read)
	cn("postgres_blocks_hit_total", "Block reads served from the buffer cache.", hit)
	cn("postgres_tuples_returned_total", "Rows returned by scans.", ret)
	cn("postgres_tuples_fetched_total", "Rows fetched by index scans.", fetched)
	cn("postgres_tuples_inserted_total", "Rows inserted.", ins)
	cn("postgres_tuples_updated_total", "Rows updated.", upd)
	cn("postgres_tuples_deleted_total", "Rows deleted.", del)
	cn("postgres_conflicts_total", "Queries canceled by recovery conflicts.", conflicts)
	cn("postgres_temp_files_total", "Temporary files created.", tempFiles)
	cn("postgres_temp_bytes_total", "Bytes written to temporary files.", tempBytes)
	cn("postgres_deadlocks_total", "Deadlocks detected.", deadlocks)

	states := map[string]float64{}
	if err := scanPairs(ctx, pool, `SELECT COALESCE(state, 'background'), count(*)::float8 FROM pg_stat_activity WHERE datname = current_database() GROUP BY 1`, states); err != nil {
		return err
	}
	sg := with(emit, "state")
	for _, s := range []string{"active", "idle", "idle in transaction", "idle in transaction (aborted)", "fastpath function call", "disabled"} {
		sg.gauge("postgres_connections", "Connections by state.", states[s], s)
	}
	var waiting int64
	var longest float64
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM pg_locks WHERE NOT granted),
		COALESCE((SELECT max(extract(epoch FROM now() - xact_start)) FROM pg_stat_activity WHERE datname = current_database() AND state <> 'idle' AND pid <> pg_backend_pid()), 0)::float8`).Scan(&waiting, &longest); err != nil {
		return err
	}
	emit(gv("postgres_locks_waiting", "Lock requests waiting to be granted.", float64(waiting)))
	emit(gv("postgres_longest_transaction_seconds", "Age of the oldest running transaction.", longest))

	tables, err := pool.Query(ctx, `SELECT relname, n_live_tup, n_dead_tup, pg_total_relation_size(relid), seq_scan, COALESCE(idx_scan, 0),
		n_tup_ins, n_tup_upd, n_tup_del, COALESCE(extract(epoch FROM greatest(last_autovacuum, last_vacuum))::float8, 0)
		FROM pg_stat_user_tables`)
	if err != nil {
		return err
	}
	defer tables.Close()
	t := with(emit, "table")
	for tables.Next() {
		var name string
		var live, dead, bytes, seq, idx, tins, tupd, tdel int64
		var vac float64
		if err := tables.Scan(&name, &live, &dead, &bytes, &seq, &idx, &tins, &tupd, &tdel, &vac); err != nil {
			return err
		}
		t.gauge("postgres_table_rows", "Estimated live rows.", float64(live), name)
		t.gauge("postgres_table_dead_rows", "Estimated dead rows waiting for vacuum.", float64(dead), name)
		t.gauge("postgres_table_size_bytes", "Table size including indexes and TOAST.", float64(bytes), name)
		t.counter("postgres_table_seq_scans_total", "Sequential scans.", float64(seq), name)
		t.counter("postgres_table_index_scans_total", "Index scans.", float64(idx), name)
		t.counter("postgres_table_inserts_total", "Rows inserted.", float64(tins), name)
		t.counter("postgres_table_updates_total", "Rows updated.", float64(tupd), name)
		t.counter("postgres_table_deletes_total", "Rows deleted.", float64(tdel), name)
		if vac > 0 {
			t.gauge("postgres_table_last_vacuum_timestamp_seconds", "When the table was last vacuumed.", vac, name)
		}
	}
	if err := tables.Err(); err != nil {
		return err
	}

	h, err := queryInts(ctx, pool, 3, `SELECT count(*), COALESCE(extract(epoch FROM min(hour))::bigint, 0), COALESCE(extract(epoch FROM max(hour))::bigint, 0) FROM traffic_hourly`)
	if err != nil {
		return err
	}
	emit(gv("traffic_history_rows", "Rows in the hourly traffic table.", float64(h[0])))
	if h[1] > 0 {
		emit(gv("traffic_history_oldest_timestamp_seconds", "Hour of the oldest traffic row kept.", float64(h[1])))
		emit(gv("traffic_history_newest_timestamp_seconds", "Hour of the newest traffic row.", float64(h[2])))
	}
	return nil
}
