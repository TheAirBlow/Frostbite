#!/usr/bin/env python3
"""Builds dashboards/frostbite.json. Run it again after changing a panel: python3 docker/grafana/build_dashboard.py"""
import json
import pathlib

DS = {"type": "prometheus", "uid": "prometheus"}
NODE = 'node=~"$node"'
DAEMON = 'node=~"$node",daemon=~"$daemon"'

# one colour per meaning, so the same thing looks the same on every panel
DOWN, UP, GOOD, WARN, BAD, MUTED = "#4C9AFF", "#F5A623", "#3FB27F", "#E8A33D", "#E5534B", "#8A94A6"
STATUS = {"active": GOOD, "on_hold": "#7AA2F7", "limited": WARN, "expired": BAD, "disabled": MUTED}

_id = 0
def nid():
    global _id
    _id += 1
    return _id

def tgt(expr, legend="", ref="A", instant=False, fmt=None):
    t = {"datasource": DS, "expr": expr, "legendFormat": legend, "refId": ref, "editorMode": "code"}
    if instant:
        t["instant"], t["range"] = True, False
    if fmt:
        t["format"] = fmt
    return t

def targets(items, instant=False, fmt=None):
    out = []
    for i, it in enumerate(items):
        if isinstance(it, str):
            it = (it, "")
        out.append(tgt(it[0], it[1], chr(65 + i), instant, fmt))
    return out

def thresholds(steps):
    """steps: [(value or None, colour)]"""
    return {"mode": "absolute", "steps": [{"value": v, "color": c} for v, c in steps]}

def by_name(regex, props):
    return {"matcher": {"id": "byRegexp", "options": regex}, "properties": props}

def color_override(regex, colour):
    return by_name(regex, [{"id": "color", "value": {"mode": "fixed", "fixedColor": colour}}])

def base(kind, title, items, w, h, unit=None, desc=None, instant=False, fmt=None):
    p = {
        "id": nid(), "type": kind, "title": title, "datasource": DS,
        "targets": targets(items, instant, fmt), "gridPos": {"w": w, "h": h, "x": 0, "y": 0},
        "fieldConfig": {"defaults": {}, "overrides": []}, "options": {},
    }
    if desc:
        p["description"] = desc
    if unit:
        p["fieldConfig"]["defaults"]["unit"] = unit
    return p

def timeseries(title, items, unit=None, w=12, h=8, stack=False, desc=None, lo=None, hi=None, fill=12, overrides=(),
               table_legend=False, bars=False, decimals=None, thresholds_=None, points=False, line=1.5, step=False):
    p = base("timeseries", title, items, w, h, unit, desc)
    d = p["fieldConfig"]["defaults"]
    d["custom"] = {
        "drawStyle": "bars" if bars else "line", "lineInterpolation": "stepAfter" if step else "smooth", "lineWidth": line,
        "fillOpacity": fill, "showPoints": "always" if points else "never", "pointSize": 4, "spanNulls": False,
        "stacking": {"mode": "normal" if stack else "none", "group": "A"},
        "axisBorderShow": False, "gradientMode": "opacity" if fill else "none",
    }
    if lo is not None:
        d["min"] = lo
    if hi is not None:
        d["max"] = hi
    if decimals is not None:
        d["decimals"] = decimals
    if thresholds_:
        d["thresholds"] = thresholds(thresholds_)
        d["custom"]["thresholdsStyle"] = {"mode": "dashed"}
    p["fieldConfig"]["overrides"] = list(overrides)
    p["options"] = {
        "legend": {"displayMode": "table" if table_legend else "list", "placement": "bottom", "showLegend": True,
                   "calcs": ["lastNotNull", "max"] if table_legend else []},
        "tooltip": {"mode": "multi", "sort": "desc"},
    }
    return p

def stat(title, expr, unit=None, w=4, h=4, steps=None, desc=None, mappings=None, decimals=None, instant=False,
         text="auto", spark=True, color="value", reduce="lastNotNull", fixed=None):
    p = base("stat", title, [expr], w, h, unit, desc, instant)
    d = p["fieldConfig"]["defaults"]
    d["thresholds"] = thresholds(steps or [(None, "#5794F2")])
    d["color"] = {"mode": "fixed", "fixedColor": fixed} if fixed else {"mode": "thresholds"}
    if mappings:
        d["mappings"] = mappings
    if decimals is not None:
        d["decimals"] = decimals
    d["noValue"] = "–"
    p["options"] = {
        "reduceOptions": {"calcs": [reduce], "fields": "", "values": False}, "textMode": text, "colorMode": color,
        "graphMode": "area" if spark and not instant else "none", "justifyMode": "auto", "orientation": "auto",
    }
    return p

def gauge(title, expr, unit="percentunit", w=4, h=6, lo=0, hi=1, steps=None, desc=None, instant=True):
    p = base("gauge", title, [expr], w, h, unit, desc, instant)
    d = p["fieldConfig"]["defaults"]
    d["min"], d["max"] = lo, hi
    d["thresholds"] = thresholds(steps or [(None, GOOD), (0.7, WARN), (0.9, BAD)])
    d["color"] = {"mode": "thresholds"}
    p["options"] = {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}, "showThresholdLabels": False, "showThresholdMarkers": True}
    return p

def bargauge(title, items, unit=None, w=8, h=8, lo=0, hi=None, steps=None, desc=None, mode="gradient", horizontal=True,
             overrides=(), colour=None, decimals=None):
    p = base("bargauge", title, items, w, h, unit, desc, instant=True)
    d = p["fieldConfig"]["defaults"]
    d["min"] = lo
    if hi is not None:
        d["max"] = hi
    d["thresholds"] = thresholds(steps or [(None, "#5794F2")])
    d["color"] = {"mode": "fixed", "fixedColor": colour} if colour else ({"mode": "thresholds"} if steps else {"mode": "palette-classic"})
    if decimals is not None:
        d["decimals"] = decimals
    d["noValue"] = "0"
    p["fieldConfig"]["overrides"] = list(overrides)
    p["options"] = {
        "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}, "displayMode": mode,
        "orientation": "horizontal" if horizontal else "vertical", "showUnfilled": True, "valueMode": "color", "namePlacement": "auto",
        "minVizHeight": 12, "minVizWidth": 8, "sizing": "auto",
    }
    return p

def pie(title, items, unit=None, w=6, h=8, desc=None, overrides=(), donut=True):
    p = base("piechart", title, items, w, h, unit, desc, instant=True)
    p["fieldConfig"]["defaults"]["color"] = {"mode": "palette-classic"}
    p["fieldConfig"]["defaults"]["noValue"] = "0"
    p["fieldConfig"]["overrides"] = list(overrides)
    p["options"] = {
        "pieType": "donut" if donut else "pie", "displayLabels": ["percent"], "tooltip": {"mode": "single", "sort": "none"},
        "legend": {"displayMode": "table", "placement": "right", "showLegend": True, "values": ["value"]},
        "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
    }
    return p

def table(title, items, w=24, h=9, hide=(), rename=None, units=None, sort=None, desc=None, order=None, extra=(), mappings=None):
    """items: instant queries that share the same label set; they are merged into one row per series."""
    p = base("table", title, items, w, h, None, desc, instant=True, fmt="table")
    exclude = {"Time": True, "__name__": True, "job": True, "instance": True}
    for k in hide:
        exclude[k] = True
    organize = {"id": "organize", "options": {"excludeByName": exclude, "renameByName": rename or {}, "indexByName": {n: i for i, n in enumerate(order or [])}}}
    p["transformations"] = [{"id": "merge", "options": {}}, organize, *extra]
    overrides = []
    for name, unit in (units or {}).items():
        overrides.append({"matcher": {"id": "byName", "options": name}, "properties": [{"id": "unit", "value": unit}]})
    for name, props in (mappings or {}).items():
        overrides.append({"matcher": {"id": "byName", "options": name}, "properties": props})
    p["fieldConfig"]["overrides"] = overrides
    p["fieldConfig"]["defaults"]["custom"] = {"align": "auto", "cellOptions": {"type": "auto"}, "filterable": True}
    p["options"] = {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}}
    if sort:
        p["options"]["sortBy"] = [{"displayName": sort[0], "desc": sort[1]}]
    return p

def cell_color(mapping):
    """a value mapping that tints a table cell: {value: (text, colour)}"""
    return [
        {"id": "custom.cellOptions", "value": {"type": "color-background", "mode": "basic"}},
        {"id": "mappings", "value": [{"type": "value", "options": {str(k): {"text": t, "color": c, "index": i} for i, (k, (t, c)) in enumerate(mapping.items())}}]},
    ]

def timeline(title, items, w=24, h=7, desc=None, mappings=None):
    p = base("state-timeline", title, items, w, h, None, desc)
    p["fieldConfig"]["defaults"].update({
        "custom": {"fillOpacity": 80, "lineWidth": 0}, "color": {"mode": "thresholds"},
        "mappings": mappings or [{"type": "value", "options": {"0": {"text": "down", "color": BAD, "index": 0}, "1": {"text": "up", "color": GOOD, "index": 1}}}],
        "thresholds": thresholds([(None, BAD), (1, GOOD)]),
    })
    p["options"] = {"mergeValues": True, "showValue": "never", "alignValue": "center", "rowHeight": 0.8, "legend": {"showLegend": False},
                    "tooltip": {"mode": "single", "sort": "none"}}
    return p

def heatmap(title, expr, unit="s", w=12, h=8, desc=None):
    p = base("heatmap", title, [(expr, "{{le}}")], w, h, None, desc, fmt="heatmap")
    p["targets"][0]["format"] = "heatmap"
    p["fieldConfig"]["defaults"]["custom"] = {"scaleDistribution": {"type": "linear"}}
    p["options"] = {
        "calculate": False, "color": {"mode": "scheme", "scheme": "Turbo", "fill": "dark-orange", "scale": "exponential", "exponent": 0.5, "steps": 64, "reverse": False},
        "yAxis": {"axisPlacement": "left", "unit": unit}, "cellGap": 1, "legend": {"show": True},
        "tooltip": {"mode": "single", "yHistogram": True, "showColorScale": True}, "rowsFrame": {"layout": "auto"}, "filterValues": {"le": 1e-9},
    }
    return p

def text(title, md, w=24, h=3):
    p = base("text", title, [], w, h)
    p["targets"] = []
    p["options"] = {"mode": "markdown", "content": md}
    p["transparent"] = True
    return p

def quantiles(metric, by="", flt="", qs=(0.5, 0.95, 0.99)):
    """histogram_quantile targets for a histogram metric"""
    group = f"le, {by}" if by else "le"
    sel = f"{{{flt}}}" if flt else ""
    legend = f" {{{{{by}}}}}" if by else ""
    return [(f"histogram_quantile({q}, sum by ({group}) (rate({metric}_bucket{sel}[$__rate_interval])))", f"p{int(q * 100)}{legend}") for q in qs]

def seconds_overrides(*names):
    return []

# ---------------------------------------------------------------------------------------------------------------------

rows = []  # (title, collapsed, [panels])

def row(title, collapsed, panels):
    rows.append((title, collapsed, panels))

UP_MAP = [{"type": "value", "options": {"0": {"text": "DOWN", "color": BAD, "index": 0}, "1": {"text": "UP", "color": GOOD, "index": 1}}}]
YESNO = [{"type": "value", "options": {"0": {"text": "no", "color": MUTED, "index": 0}, "1": {"text": "yes", "color": GOOD, "index": 1}}}]
STATUS_OVR = [color_override(k, v) for k, v in STATUS.items()]

# ----- overview ------------------------------------------------------------------------------------------------------
row("Overview", False, [
    stat("Panel", 'max(up{job="frostbite"})', mappings=UP_MAP, steps=[(None, BAD), (1, GOOD)], spark=False, desc="Whether Prometheus can scrape the panel.", instant=True),
    stat("Panel uptime", "time() - frostbite_start_time_seconds", "s", steps=[(None, WARN), (300, GOOD)], spark=False, instant=True),
    stat("Version", "frostbite_build_info", w=4, text="name", fixed="#7AA2F7", spark=False, instant=True, color="none")
        | {"targets": [tgt("frostbite_build_info", "{{version}} · {{revision}}", instant=True)]},
    stat("Users", "frostbite_users_count", fixed="#7AA2F7"),
    stat("Online now", "frostbite_online_users", fixed=GOOD, desc="Users with a live connection right now, as reported by the daemons."),
    stat("Active users", 'frostbite_users{status="active"}', fixed=GOOD),
    stat("Daemons online", "sum(frostbite_daemon_up and on(daemon_id) frostbite_daemon_enabled == 1) or vector(0)", steps=[(None, BAD), (1, GOOD)],
         desc="Enabled daemons with an open link."),
    stat("Daemons offline", "count(frostbite_daemon_up == 0 and on(daemon_id) frostbite_daemon_enabled == 1) or vector(0)", steps=[(None, GOOD), (1, BAD)]),
    stat("Download now", 'sum(rate(frostbite_traffic_billed_bytes_total{direction="down"}[$__rate_interval])) or vector(0)', "Bps", fixed=DOWN,
         desc="Billed traffic towards users, after each node's multiplier."),
    stat("Upload now", 'sum(rate(frostbite_traffic_billed_bytes_total{direction="up"}[$__rate_interval])) or vector(0)', "Bps", fixed=UP),
    stat("Traffic, last 24 h", 'sum(frostbite_node_traffic_window_bytes{window="24h"})', "bytes", fixed="#7AA2F7", instant=True,
         desc="Read from the hourly traffic table, so it is right even right after a restart."),
    stat("Alerts firing", 'count(ALERTS{alertstate="firing"}) or vector(0)', steps=[(None, GOOD), (1, BAD)], instant=True),
    timeseries("Throughput", [('sum(rate(frostbite_traffic_billed_bytes_total{direction="down"}[$__rate_interval]))', "download"),
                              ('sum(rate(frostbite_traffic_billed_bytes_total{direction="up"}[$__rate_interval]))', "upload")], "Bps", w=12,
               overrides=[color_override("download", DOWN), color_override("upload", UP)], table_legend=True,
               desc="Billed traffic over every node. Counted from usage reports, so it starts when the panel does."),
    timeseries("People and daemons", [("frostbite_online_users", "online users"), ("frostbite_users_seen{within=\"1h\"}", "seen in the last hour"),
                                      ("sum(frostbite_daemon_up)", "daemons online")], w=12, table_legend=True,
               desc="'Online users' is live from the daemons. 'Seen in the last hour' counts users whose traffic was booked."),
])

# ----- users ---------------------------------------------------------------------------------------------------------
USER_JOIN = "* on(user) group_left(status, plan, owner) frostbite_user_info"
def user_series(metric, extra=""):
    return f"({metric} {USER_JOIN})" + extra

row("Users", False, [
    pie("By status", ["sum by (status) (frostbite_users)"], w=6, overrides=STATUS_OVR),
    timeseries("Users over time", [("frostbite_users", "{{status}}")], w=12, stack=True, overrides=STATUS_OVR, fill=40, desc="Growth, and what happens to users as they hit limits or expire."),
    bargauge("Expiring soon", [('frostbite_users_expiring{within="1d"}', "within 1 day"), ('frostbite_users_expiring{within="3d"}', "within 3 days"),
                               ('frostbite_users_expiring{within="7d"}', "within 7 days"), ('frostbite_users_expiring{within="30d"}', "within 30 days")],
             w=6, steps=[(None, GOOD), (1, WARN), (10, BAD)], desc="Cumulative: a user ending tomorrow is in every row."),
    stat("Blocked", "frostbite_users_blocked", steps=[(None, GOOD), (1, WARN)], desc="Cut off for using more addresses than their limit allows."),
    stat("Over their limit", "frostbite_users_over_limit", steps=[(None, GOOD), (1, WARN)], desc="At or over the traffic limit. They become 'limited' on the next enforcement pass."),
    stat("Never connected", "frostbite_users_never_seen", fixed=MUTED),
    stat("Unlimited traffic", "frostbite_users_unlimited_traffic", fixed="#7AA2F7"),
    stat("Without expiry", "frostbite_users_without_expiry", fixed="#7AA2F7"),
    stat("Linked to Telegram", "frostbite_users_with_telegram", fixed="#7AA2F7"),
    bargauge("How much of their limit users used", [("frostbite_users_by_usage", "{{usage}}")], w=8, h=7,
             overrides=[color_override("<10%", GOOD), color_override("10-50%", GOOD), color_override("50-80%", "#9BC53D"), color_override("80-95%", WARN),
                        color_override("95-100%", "#E8743B"), color_override(">=100%", BAD)], desc="Only users that have a traffic limit."),
    timeseries("Activity", [('frostbite_users_seen{within="3m"}', "last 3 minutes"), ('frostbite_users_seen{within="1h"}', "last hour"),
                            ('frostbite_users_seen{within="24h"}', "last 24 hours"), ('frostbite_users_seen{within="7d"}', "last 7 days")], w=8, h=7,
               desc="Users whose traffic was booked within each window."),
    bargauge("New users", [('frostbite_users_created{within="24h"}', "last 24 hours"), ('frostbite_users_created{within="7d"}', "last 7 days"),
                           ('frostbite_users_created{within="30d"}', "last 30 days")], w=8, h=7, colour="#7AA2F7"),
    pie("Plans", ["sum by (plan) (frostbite_users_by_plan)"], w=6),
    pie("Owners", ["sum by (owner) (frostbite_owner_users)"], w=6, desc="Who created the users: admins and resellers."),
    pie("Reset schedule", ["sum by (strategy) (frostbite_users_by_reset_strategy)"], w=6),
    bargauge("Squads", [("frostbite_squad_users", "{{squad}}")], w=6, colour="#7AA2F7"),
    pie("Client apps", ["sum by (client) (frostbite_users_by_client)"], w=6, desc="From the user agent of each user's last subscription fetch."),
    pie("Device platforms", ["sum by (platform) (frostbite_devices_by_platform)"], w=6),
    timeseries("Subscription fetches by users", [('frostbite_users_subscription_fetched{within="5m"}', "last 5 minutes"), ('frostbite_users_subscription_fetched{within="1h"}', "last hour"),
                                                  ('frostbite_users_subscription_fetched{within="24h"}', "last 24 hours")], w=6),
    stat("Devices registered", "frostbite_devices", fixed="#7AA2F7", desc="Users with a device limit register each client the first time it fetches."),
    stat("With device limit", "frostbite_users_with_device_limit", fixed="#7AA2F7"),
    stat("With address limit", "frostbite_users_with_ip_limit", fixed="#7AA2F7"),
    stat("Never fetched sub", "frostbite_users_subscription_never_fetched", fixed=MUTED, desc="Nobody opened their subscription link yet."),
    stat("Online addresses", "frostbite_online_user_addresses", fixed=GOOD, desc="Distinct source addresses over all online users."),
    stat("Tags in use", "count(frostbite_users_by_tag) or vector(0)", fixed="#7AA2F7"),
    table("Heaviest users this period",
          [("topk(20, " + user_series("frostbite_user_traffic_used_bytes") + ")", ""),
           (user_series("frostbite_user_traffic_limit_bytes") + " and on(user) topk(20, frostbite_user_traffic_used_bytes)", ""),
           (user_series("frostbite_user_traffic_used_bytes / (frostbite_user_traffic_limit_bytes > 0)") + " and on(user) topk(20, frostbite_user_traffic_used_bytes)", ""),
           (user_series("(frostbite_user_expire_timestamp_seconds - time())") + " and on(user) topk(20, frostbite_user_traffic_used_bytes)", "")],
          w=12, h=10, hide=["Value #E"], rename={"Value #A": "Used", "Value #B": "Limit", "Value #C": "Of limit", "Value #D": "Expires in", "user": "User", "status": "Status", "plan": "Plan", "owner": "Owner"},
          units={"Used": "bytes", "Limit": "bytes", "Of limit": "percentunit", "Expires in": "s"}, sort=("Used", True),
          order=["User", "Status", "Plan", "Owner", "Used", "Limit", "Of limit", "Expires in"],
          mappings={"Status": cell_color({k: (k, v) for k, v in STATUS.items()})},
          desc="Needs per-user metrics (on by default). Traffic this period resets according to each user's schedule."),
    table("Expiring within 14 days",
          [(user_series("(frostbite_user_expire_timestamp_seconds - time())") + " < 14 * 86400 > 0", ""),
           (user_series("frostbite_user_traffic_used_bytes") + " and on(user) ((frostbite_user_expire_timestamp_seconds - time()) < 14 * 86400 > 0)", "")],
          w=12, h=10, rename={"Value #A": "Expires in", "Value #B": "Used", "user": "User", "status": "Status", "plan": "Plan", "owner": "Owner"},
          units={"Expires in": "s", "Used": "bytes"}, sort=("Expires in", False), order=["User", "Status", "Plan", "Owner", "Expires in", "Used"],
          mappings={"Status": cell_color({k: (k, v) for k, v in STATUS.items()})}),
    table("Connected right now",
          [(user_series("frostbite_user_online_addresses"), ""), (user_series("frostbite_user_traffic_used_bytes") + " and on(user) frostbite_user_online_addresses", "")],
          w=12, h=9, rename={"Value #A": "Addresses", "Value #B": "Used", "user": "User", "status": "Status", "plan": "Plan", "owner": "Owner"}, units={"Used": "bytes"},
          sort=("Addresses", True), order=["User", "Status", "Plan", "Owner", "Addresses", "Used"]),
    table("Blocked for too many addresses",
          [(user_series("(frostbite_user_blocked_until_timestamp_seconds - time())"), ""), (user_series("frostbite_user_ip_limit") + " and on(user) frostbite_user_blocked_until_timestamp_seconds", "")],
          w=12, h=9, rename={"Value #A": "Blocked for", "Value #B": "Address limit", "user": "User", "status": "Status", "plan": "Plan", "owner": "Owner"}, units={"Blocked for": "s"},
          order=["User", "Status", "Owner", "Blocked for", "Address limit"]),
])

# ----- traffic -------------------------------------------------------------------------------------------------------
BILLED = "frostbite_traffic_billed_bytes_total"
row("Traffic", False, [
    timeseries("Download by node", [(f'sum by (node) (rate({BILLED}{{{NODE},direction="down"}}[$__rate_interval]))', "{{node}}")], "Bps", w=12, stack=True, fill=35, table_legend=True),
    timeseries("Upload by node", [(f'sum by (node) (rate({BILLED}{{{NODE},direction="up"}}[$__rate_interval]))', "{{node}}")], "Bps", w=12, stack=True, fill=35, table_legend=True),
    stat("Last hour", f'sum(frostbite_node_traffic_window_bytes{{{NODE},window="1h"}})', "bytes", fixed="#7AA2F7", instant=True),
    stat("Last 24 hours", f'sum(frostbite_node_traffic_window_bytes{{{NODE},window="24h"}})', "bytes", fixed="#7AA2F7", instant=True),
    stat("Last 7 days", f'sum(frostbite_node_traffic_window_bytes{{{NODE},window="7d"}})', "bytes", fixed="#7AA2F7", instant=True),
    stat("Last 30 days", f'sum(frostbite_node_traffic_window_bytes{{{NODE},window="30d"}})', "bytes", fixed="#7AA2F7", instant=True),
    stat("All recorded", f'sum(frostbite_node_traffic_window_bytes{{{NODE},window="all"}})', "bytes", fixed="#7AA2F7", instant=True,
         desc="Everything in the hourly table, which is kept for 400 days."),
    stat("Download share, 24 h", f'sum(frostbite_node_traffic_window_bytes{{{NODE},window="24h",direction="down"}}) / clamp_min(sum(frostbite_node_traffic_window_bytes{{{NODE},window="24h"}}), 1)',
         "percentunit", fixed=DOWN, instant=True),
    pie("Traffic by node, 7 days", [(f'sum by (node) (frostbite_node_traffic_window_bytes{{{NODE},window="7d"}})', "{{node}}")], "bytes", w=6),
    bargauge("Traffic by node", [(f'sum by (node) (frostbite_node_traffic_window_bytes{{{NODE},window="24h"}})', "{{node}} · 24 h"),
                                 (f'sum by (node) (frostbite_node_traffic_window_bytes{{{NODE},window="30d"}})', "{{node}} · 30 d")], "bytes", w=9, h=8),
    bargauge("Node traffic limit used", [(f'frostbite_node_traffic_used_bytes_total{{{NODE}}} / (frostbite_node_traffic_limit_bytes{{{NODE}}} > 0)', "{{node}}")], "percentunit", w=9, h=8, hi=1,
             steps=[(None, GOOD), (0.7, WARN), (0.9, BAD)], desc="Nodes with a traffic limit only. Counts raw traffic, before the multiplier."),
    timeseries("Rolling 24 hour traffic", [(f'sum(increase({BILLED}{{{NODE},direction="down"}}[1d]))', "download"), (f'sum(increase({BILLED}{{{NODE},direction="up"}}[1d]))', "upload")],
               "bytes", w=12, overrides=[color_override("download", DOWN), color_override("upload", UP)],
               desc="Traffic of the 24 hours before each point, from the panel's own counters."),
    timeseries("Raw and billed throughput", [(f'sum(rate(frostbite_traffic_raw_bytes_total{{{NODE}}}[$__rate_interval]))', "raw (as reported)"),
                                             (f'sum(rate({BILLED}{{{NODE}}}[$__rate_interval]))', "billed (after multiplier)")], "Bps", w=12,
               desc="They differ when a node has a multiplier other than 1, or when usage belongs to users that no longer exist."),
    timeseries("Heaviest users", [("topk(10, sum by (user) (rate(frostbite_user_traffic_lifetime_bytes_total[$__rate_interval])))", "{{user}}")], "Bps", w=12, table_legend=True,
               desc="Per-user throughput. Needs per-user metrics, and resolves to the scrape interval."),
    timeseries("Users hitting limits", [("sum(increase(frostbite_traffic_limit_hits_total[$__rate_interval]))", "usage reports at or over the limit"),
                                        ('sum(increase(frostbite_ip_limit_blocks_total[$__rate_interval]))', "address limit blocks"),
                                        ('sum(increase(frostbite_quota_user_changes_total{change="users limited"}[$__rate_interval]))', "users limited"),
                                        ('sum(increase(frostbite_quota_user_changes_total{change="users expired"}[$__rate_interval]))', "users expired"),
                                        ('sum(increase(frostbite_quota_user_changes_total{change="traffic reset"}[$__rate_interval]))', "traffic resets")], w=12, bars=True, fill=60, line=0),
    table("Nodes",
          [(f'frostbite_node_info{{{NODE}}}', ""),
           (f'frostbite_node_enabled{{{NODE}}}', ""),
           (f'frostbite_node_traffic_multiplier{{{NODE}}}', ""),
           (f'sum by (node_id, node) (frostbite_node_traffic_window_bytes{{{NODE},window="24h",direction="down"}})', ""),
           (f'sum by (node_id, node) (frostbite_node_traffic_window_bytes{{{NODE},window="24h",direction="up"}})', ""),
           (f'frostbite_node_active_users{{{NODE},window="24h"}}', ""),
           (f'frostbite_node_traffic_used_bytes_total{{{NODE}}}', ""),
           (f'frostbite_node_traffic_limit_bytes{{{NODE}}}', "")],
          w=24, h=7, hide=["window", "Value #A"],
          rename={"Value #B": "Enabled", "Value #C": "Multiplier", "Value #D": "Down 24 h", "Value #E": "Up 24 h", "Value #F": "Users 24 h", "Value #G": "Raw total", "Value #H": "Limit",
                  "node": "Node", "node_id": "ID", "address": "Address", "country": "Country", "tags": "Tags"},
          units={"Down 24 h": "bytes", "Up 24 h": "bytes", "Raw total": "bytes", "Limit": "bytes"},
          order=["Node", "Address", "Country", "Tags", "Enabled", "Multiplier", "Down 24 h", "Up 24 h", "Users 24 h", "Raw total", "Limit"],
          mappings={"Enabled": cell_color({"0": ("no", MUTED), "1": ("yes", GOOD)})}, sort=("Down 24 h", True)),
    table("Most traffic ever", [("topk(20, " + user_series("frostbite_user_traffic_lifetime_bytes_total") + ")", "")], w=12, h=9,
          rename={"Value": "Lifetime", "user": "User", "status": "Status", "plan": "Plan", "owner": "Owner"}, units={"Lifetime": "bytes"}, sort=("Lifetime", True),
          order=["User", "Status", "Plan", "Owner", "Lifetime"], mappings={"Status": cell_color({k: (k, v) for k, v in STATUS.items()})}),
    bargauge("Traffic by owner", [("sort_desc(frostbite_owner_users_traffic_used_bytes)", "{{owner}}")], "bytes", w=12, h=9, colour="#7AA2F7",
             desc="Traffic used this period by the users of each administrator."),
])

# ----- nodes and daemons ---------------------------------------------------------------------------------------------
DAEMON_LEGEND = "{{node}} · {{daemon}}"
row("Nodes and daemons", False, [
    timeline("Daemon link", [(f'frostbite_daemon_up{{{DAEMON}}}', DAEMON_LEGEND)], w=24, h=7,
             desc="Green while the daemon has an open link to the panel. A daemon that is disabled shows as down."),
    table("Daemons",
          [(f'frostbite_daemon_info{{{DAEMON}}}', ""),
           (f'frostbite_daemon_up{{{DAEMON}}}', ""),
           (f'frostbite_daemon_enabled{{{DAEMON}}}', ""),
           (f'frostbite_daemon_in_sync{{{DAEMON}}}', ""),
           (f'frostbite_daemon_applied_revision{{{DAEMON}}}', ""),
           (f'frostbite_daemon_desired_revision{{{DAEMON}}}', ""),
           (f'frostbite_daemon_enabled_inbounds{{{DAEMON}}}', ""),
           (f'frostbite_daemon_online_users{{{DAEMON}}}', ""),
           (f'frostbite_daemon_connected_since_timestamp_seconds{{{DAEMON}}} * 1000', ""),
           (f'frostbite_daemon_last_seen_timestamp_seconds{{{DAEMON}}} * 1000', "")],
          w=24, h=9, hide=["Value #A", "daemon_id", "node_id", "log_level"],
          rename={"Value #B": "Link", "Value #C": "Enabled", "Value #D": "In sync", "Value #E": "Applied", "Value #F": "Wanted", "Value #G": "Inbounds", "Value #H": "Users",
                  "Value #I": "Connected since", "Value #J": "Last seen", "node": "Node", "daemon": "Daemon", "kind": "Kind", "core_version": "Core", "agent_version": "Agent",
                  "hostname": "Host", "os": "OS", "arch": "Arch", "kernel": "Kernel"},
          units={}, order=["Node", "Daemon", "Kind", "Link", "In sync", "Enabled", "Core", "Agent", "Applied", "Wanted", "Inbounds", "Users", "Host", "OS", "Arch", "Kernel", "Connected since", "Last seen"],
          mappings={"Link": cell_color({"0": ("down", BAD), "1": ("up", GOOD)}), "In sync": cell_color({"0": ("no", WARN), "1": ("yes", GOOD)}),
                    "Enabled": cell_color({"0": ("no", MUTED), "1": ("yes", GOOD)}),
                    "Connected since": [{"id": "unit", "value": "dateTimeFromNow"}], "Last seen": [{"id": "unit", "value": "dateTimeFromNow"}]},
          sort=("Node", False),
          desc="'Connected since' and 'Last seen' are relative to now; 'In sync' means the daemon runs the revision the panel wants and reported no error."),
    table("Configuration errors", [(f'frostbite_daemon_last_error_info{{{DAEMON}}}', "")], w=24, h=5,
          hide=["Value", "daemon_id", "node_id"], rename={"node": "Node", "daemon": "Daemon", "kind": "Kind", "error": "Error"}, order=["Node", "Daemon", "Kind", "Error"],
          desc="Why a daemon refused its last configuration. Empty when everything applies."),
    bargauge("Revisions behind", [(f'frostbite_daemon_desired_revision{{{DAEMON}}} - frostbite_daemon_applied_revision{{{DAEMON}}}', DAEMON_LEGEND)], w=8, h=7,
             steps=[(None, GOOD), (1, WARN), (5, BAD)], desc="How far each daemon trails the configuration the panel wants it to run."),
    timeseries("Reconnects", [("sum by (kind) (increase(frostbite_link_connections_total[$__rate_interval]))", "{{kind}} connected"),
                              ("sum by (kind) (increase(frostbite_link_disconnections_total[$__rate_interval]))", "{{kind}} disconnected")], w=8, h=7, bars=True, fill=60, line=0,
               desc="A link that keeps coming back points at a flaky network or a daemon crash loop."),
    timeseries("Refused daemon connections", [("sum by (reason) (increase(frostbite_link_rejected_total[$__rate_interval]))", "{{reason}}")], w=8, h=7, bars=True, fill=60, line=0,
               desc="Missing or unknown tokens, failed upgrades and bad hellos."),
    timeseries("Users per daemon", [(f'frostbite_daemon_online_users{{{DAEMON}}}', DAEMON_LEGEND)], w=12, stack=True, fill=30),
    timeseries("Addresses per daemon", [(f'frostbite_daemon_online_addresses{{{DAEMON}}}', DAEMON_LEGEND)], w=12, stack=True, fill=30),
    text("Host health", "Reported by each daemon every 15 seconds. Daemons on the same machine report the same host.", h=2),
    timeseries("CPU", [(f'frostbite_host_cpu_ratio{{{DAEMON}}}', DAEMON_LEGEND)], "percentunit", w=8, lo=0, hi=1, thresholds_=[(None, "green"), (0.9, "red")]),
    timeseries("Memory", [(f'frostbite_host_memory_used_bytes{{{DAEMON}}} / frostbite_host_memory_total_bytes{{{DAEMON}}}', DAEMON_LEGEND)], "percentunit", w=8, lo=0, hi=1,
               thresholds_=[(None, "green"), (0.92, "red")], desc="Used memory excludes reclaimable cache."),
    timeseries("Disk used", [(f'frostbite_host_disk_used_bytes{{{DAEMON}}} / frostbite_host_disk_total_bytes{{{DAEMON}}}', DAEMON_LEGEND)], "percentunit", w=8, lo=0, hi=1,
               thresholds_=[(None, "green"), (0.9, "red")], desc="The root filesystem."),
    timeseries("Network out", [(f'frostbite_host_network_up_bytes_per_second{{{DAEMON}}}', DAEMON_LEGEND)], "Bps", w=8,
               desc="Every non loopback interface, so traffic through docker bridges can be counted twice."),
    timeseries("Network in", [(f'frostbite_host_network_down_bytes_per_second{{{DAEMON}}}', DAEMON_LEGEND)], "Bps", w=8),
    timeseries("Packets", [(f'frostbite_host_network_up_packets_per_second{{{DAEMON}}}', "{{node}} · {{daemon}} out"), (f'frostbite_host_network_down_packets_per_second{{{DAEMON}}}', "{{node}} · {{daemon}} in")], "pps", w=8),
    timeseries("Load average", [(f'frostbite_host_load1{{{DAEMON}}}', "{{node}} · {{daemon}} 1m"), (f'frostbite_host_load5{{{DAEMON}}}', "{{node}} · {{daemon}} 5m"), (f'frostbite_host_load15{{{DAEMON}}}', "{{node}} · {{daemon}} 15m")], w=8),
    timeseries("Swap", [(f'frostbite_host_swap_used_bytes{{{DAEMON}}}', DAEMON_LEGEND)], "bytes", w=8, desc="Empty on hosts without swap."),
    timeseries("Disk throughput", [(f'frostbite_host_disk_read_bytes_per_second{{{DAEMON}}}', "{{node}} · {{daemon}} read"), (f'frostbite_host_disk_write_bytes_per_second{{{DAEMON}}}', "{{node}} · {{daemon}} write")], "Bps", w=8),
    timeseries("TCP connections", [(f'frostbite_host_tcp_connections{{{DAEMON}}}', "{{node}} · {{daemon}} established"), (f'frostbite_host_tcp_time_wait{{{DAEMON}}}', "{{node}} · {{daemon}} time-wait")], w=8),
    timeseries("Sockets", [(f'frostbite_host_tcp_sockets_in_use{{{DAEMON}}}', "{{node}} · {{daemon}} tcp"), (f'frostbite_host_udp_sockets_in_use{{{DAEMON}}}', "{{node}} · {{daemon}} udp")], w=8),
    timeseries("Network errors and drops", [(f'frostbite_host_network_errors_per_second{{{DAEMON}}}', DAEMON_LEGEND)], "ops", w=8, desc="Errors and drops per second, summed over interfaces."),
    timeseries("File descriptors", [(f'frostbite_host_open_files{{{DAEMON}}} / frostbite_host_max_open_files{{{DAEMON}}}', DAEMON_LEGEND)], "percentunit", w=8, lo=0, hi=1,
               thresholds_=[(None, "green"), (0.8, "red")], desc="Allocated system wide, against the kernel limit."),
    timeseries("Processes", [(f'frostbite_host_processes{{{DAEMON}}}', DAEMON_LEGEND)], w=8),
    bargauge("Host uptime", [(f'frostbite_host_uptime_seconds{{{DAEMON}}}', DAEMON_LEGEND)], "s", w=8, colour="#7AA2F7"),
    timeseries("Daemon goroutines", [(f'frostbite_agent_goroutines{{{DAEMON}}}', DAEMON_LEGEND)], w=8, desc="Of the daemon program itself, not the core it drives."),
    timeseries("Daemon heap", [(f'frostbite_agent_heap_bytes{{{DAEMON}}}', DAEMON_LEGEND)], "bytes", w=8),
    bargauge("Daemon uptime", [(f'frostbite_agent_uptime_seconds{{{DAEMON}}}', DAEMON_LEGEND)], "s", w=8, colour="#7AA2F7"),
    timeseries("Report age", [(f'frostbite_host_sample_age_seconds{{{DAEMON}}}', DAEMON_LEGEND)], "s", w=12, thresholds_=[(None, "green"), (60, "red")],
               desc="Seconds since the daemon last sent its health. Should stay under 15."),
    timeseries("Daemon link traffic", [('sum(rate(frostbite_link_received_bytes_total[$__rate_interval]))', "from daemons"), ('sum(rate(frostbite_link_sent_bytes_total[$__rate_interval]))', "to daemons")], "Bps", w=12),
    bargauge("Certificates, days left", [(f'(frostbite_daemon_cert_expiry_timestamp_seconds{{{DAEMON}}} - time()) / 86400', "{{node}} · {{domain}}")], "d", w=12, h=7, hi=90,
             steps=[(None, BAD), (7, WARN), (21, GOOD)], decimals=0, desc="Automatic certificates renew by themselves about 30 days before they expire."),
    table("Certificates", [(f'frostbite_daemon_cert_ok{{{DAEMON}}}', ""), (f'frostbite_daemon_cert_placeholder{{{DAEMON}}}', ""), (f'frostbite_daemon_cert_expiry_timestamp_seconds{{{DAEMON}}} * 1000', "")],
          w=12, h=7, hide=["daemon_id", "node_id"], rename={"Value #A": "Issuing", "Value #B": "Self signed", "Value #C": "Expires", "node": "Node", "daemon": "Daemon", "kind": "Kind", "domain": "Domain"},
          order=["Node", "Daemon", "Domain", "Issuing", "Self signed", "Expires"],
          mappings={"Issuing": cell_color({"0": ("failing", BAD), "1": ("ok", GOOD)}), "Self signed": cell_color({"0": ("no", GOOD), "1": ("stand-in", WARN)}), "Expires": [{"id": "unit", "value": "dateTimeFromNow"}]}),
])

# ----- configuration -------------------------------------------------------------------------------------------------
row("Configuration", True, [
    stat("Nodes", f'count(frostbite_node_info{{{NODE}}}) or vector(0)', fixed="#7AA2F7", instant=True),
    stat("Daemons", "frostbite_daemons_count", fixed="#7AA2F7"),
    stat("Inbounds", 'sum(frostbite_inbounds{system="false"}) or vector(0)', fixed="#7AA2F7", desc="Without the system inbounds that bridges create."),
    stat("Hosts", "frostbite_hosts", fixed="#7AA2F7"),
    stat("Squads", "frostbite_squads", fixed="#7AA2F7"),
    stat("Plans", "frostbite_plans", fixed="#7AA2F7"),
    pie("Inbounds by protocol", ['sum by (protocol) (frostbite_inbounds{system="false"})'], w=6),
    pie("Inbounds by transport", ['sum by (transport) (frostbite_inbounds{system="false"})'], w=6),
    pie("Inbounds by security", ['sum by (security) (frostbite_inbounds{system="false"})'], w=6),
    pie("Outbounds", ["sum by (kind) (frostbite_outbounds)"], w=6),
    bargauge("Enabled and disabled", [('sum(frostbite_inbounds{enabled="true",system="false"}) or vector(0)', "inbounds on"), ('sum(frostbite_inbounds{enabled="false",system="false"}) or vector(0)', "inbounds off"),
                                      ("frostbite_hosts_enabled", "hosts on"), ("frostbite_hosts - frostbite_hosts_enabled", "hosts off"),
                                      ("frostbite_routing_rules_enabled", "rules on"), ("frostbite_routing_rules - frostbite_routing_rules_enabled", "rules off")], w=8, h=8, colour="#7AA2F7"),
    bargauge("Routing and relays", [("frostbite_routing_rules_global", "global rules"), ("frostbite_routing_rules - frostbite_routing_rules_global", "per-daemon rules"),
                                    ("frostbite_hosts_bridged", "hosts through a bridge"), ('sum(frostbite_inbounds{behind_edge="true"}) or vector(0)', "inbounds behind an edge"),
                                    ('sum(frostbite_inbounds{system="true"}) or vector(0)', "bridge inbounds")], w=8, h=8, colour="#7AA2F7"),
    bargauge("Subscriptions", [("frostbite_subscription_templates", "templates"), ("frostbite_subscription_rules", "client rules"), ("frostbite_subscription_rules_enabled", "client rules on")], w=8, h=8, colour="#7AA2F7"),
    table("Inbounds",
          [("frostbite_inbound_info", ""), ("frostbite_inbound_enabled", ""), ("frostbite_inbound_hosts", ""), ("frostbite_inbound_squads", "")],
          w=24, h=10, hide=["Value #A", "inbound_id", "daemon_id", "node_id", "system", "behind_edge"],
          rename={"Value #B": "Enabled", "Value #C": "Hosts", "Value #D": "Squads", "tag": "Tag", "remark": "Remark", "daemon": "Daemon", "node": "Node", "protocol": "Protocol", "port": "Port", "transport": "Transport", "security": "Security"},
          order=["Node", "Daemon", "Tag", "Remark", "Protocol", "Port", "Transport", "Security", "Enabled", "Hosts", "Squads"], sort=("Node", False),
          mappings={"Enabled": cell_color({"0": ("off", MUTED), "1": ("on", GOOD)})}),
    table("Plans", [("frostbite_plan_traffic_limit_bytes", ""), ("frostbite_plan_duration_seconds", ""), ("frostbite_plan_device_limit", ""), ("frostbite_plan_ip_limit", ""), ("frostbite_plan_squads", ""),
                    ("sum by (plan) (frostbite_users_by_plan)", "")], w=12, h=7,
          rename={"Value #A": "Traffic", "Value #B": "Length", "Value #C": "Devices", "Value #D": "Addresses", "Value #E": "Squads", "Value #F": "Users", "plan": "Plan"},
          units={"Traffic": "bytes", "Length": "s"}, order=["Plan", "Traffic", "Length", "Devices", "Addresses", "Squads", "Users"], desc="A limit of 0 means unlimited."),
    table("Administrators", [("frostbite_admin_info", ""), ("frostbite_admin_users", ""), ("frostbite_admin_user_quota", ""), ("frostbite_admin_traffic_allocated_bytes", ""),
                             ("frostbite_admin_traffic_quota_bytes", ""), ("frostbite_admin_sessions", ""), ("frostbite_admin_api_tokens", "")], w=12, h=7, hide=["Value #A"],
          rename={"Value #B": "Users", "Value #C": "User quota", "Value #D": "Handed out", "Value #E": "Traffic quota", "Value #F": "Sessions", "Value #G": "Tokens", "admin": "Admin", "role": "Role", "enabled": "Enabled"},
          units={"Handed out": "bytes", "Traffic quota": "bytes"}, order=["Admin", "Role", "Enabled", "Users", "User quota", "Handed out", "Traffic quota", "Sessions", "Tokens"]),
    stat("Webhooks", "frostbite_notify_webhooks_enabled", fixed="#7AA2F7", desc="Enabled webhooks."),
    stat("Telegram bot", "frostbite_notify_telegram_enabled", mappings=YESNO, steps=[(None, MUTED), (1, GOOD)], spark=False),
    stat("Telegram admins", "frostbite_notify_telegram_admins", fixed="#7AA2F7"),
    stat("WARP", "frostbite_warp_registered", mappings=YESNO, steps=[(None, MUTED), (1, GOOD)], spark=False),
    stat("Scheduled backups", "frostbite_backup_schedule_enabled", mappings=YESNO, steps=[(None, BAD), (1, GOOD)], spark=False),
    stat("Database schema", "frostbite_db_schema_version", fixed="#7AA2F7", spark=False, desc="Latest applied migration."),
])

# ----- hub and automation --------------------------------------------------------------------------------------------
row("Configuration pushes and automation", True, [
    timeseries("Spec pushes", [("sum by (kind) (rate(frostbite_spec_pushes_total[$__rate_interval]))", "{{kind}} pushed"), ("sum(rate(frostbite_spec_revisions_total[$__rate_interval]))", "revisions created")], "ops", w=8,
               desc="A push goes out when a daemon's configuration changes or when it connects."),
    timeseries("Daemon answers", [("sum by (kind, result) (rate(frostbite_spec_acks_total[$__rate_interval]))", "{{kind}} {{result}}")], "ops", w=8,
               overrides=[color_override(".*rejected", BAD), color_override(".*applied", GOOD)]),
    timeseries("Spec builds", [("sum by (result) (rate(frostbite_spec_builds_total[$__rate_interval]))", "{{result}}")], "ops", w=8, overrides=[color_override("rejected", BAD), color_override("accepted", GOOD)],
               desc="Rejected means the panel refused to send a configuration, for example a missing certificate or an unsupported combination."),
    timeseries("Rebuild time", quantiles("frostbite_hub_rebuild_duration_seconds"), "s", w=8, desc="Recomputing every daemon's configuration. Runs after any change, bursts collapse into one pass."),
    timeseries("Rebuilds", [("sum by (result) (rate(frostbite_hub_rebuilds_total[$__rate_interval]))", "{{result}}")], "ops", w=8, overrides=[color_override("error", BAD)]),
    timeseries("Daemon commands", [("sum by (name, result) (rate(frostbite_daemon_commands_total[$__rate_interval]))", "{{name}} {{result}}")], "ops", w=8,
               desc="Restarts, log requests and connection tests started from the panel."),
    timeseries("Command time", quantiles("frostbite_daemon_command_duration_seconds", "name"), "s", w=8),
    timeseries("Reports from daemons", [("sum by (type) (rate(frostbite_daemon_reports_total[$__rate_interval]))", "{{type}}")], "ops", w=8),
    timeseries("Frames", [("sum by (type) (rate(frostbite_link_messages_received_total[$__rate_interval]))", "{{type}} in"), ("sum by (type) (rate(frostbite_link_messages_sent_total[$__rate_interval]))", "{{type}} out")], "ops", w=8),
    timeseries("Usage booking time", quantiles("frostbite_usage_ingest_duration_seconds"), "s", w=8, desc="Time to book one usage report against users, nodes and the hourly table."),
    timeseries("Usage for unknown users", [("sum(increase(frostbite_usage_unknown_users_total[$__rate_interval]))", "entries")], w=8, bars=True, fill=60, line=0,
               desc="Usage from users that were deleted while connected. A steady stream suggests a daemon with a stale configuration."),
    timeseries("Bad or dropped links", [("sum(increase(frostbite_link_bad_frames_total[$__rate_interval]))", "bad frames"), ("sum(increase(frostbite_link_dropped_total[$__rate_interval]))", "dropped for being slow")], w=8, bars=True, fill=60, line=0),
    timeseries("Enforcement changes", [("sum by (change) (increase(frostbite_quota_user_changes_total[$__rate_interval]))", "{{change}}")], w=8, bars=True, fill=60, line=0,
               desc="Users the quota loop changed: resets, expiries, limits, activations and lifted blocks."),
    timeseries("Enforcement pass", quantiles("frostbite_quota_pass_duration_seconds"), "s", w=8, desc="One pass runs every few seconds."),
    timeseries("Enforcement errors and cleanup", [("sum by (step) (increase(frostbite_quota_errors_total[$__rate_interval]))", "error: {{step}}"),
                                                  ("sum by (task, result) (increase(frostbite_housekeeping_runs_total[$__rate_interval]))", "cleanup {{task}} {{result}}")], w=8, bars=True, fill=60, line=0),
])

# ----- notifications -------------------------------------------------------------------------------------------------
row("Notifications and bot", True, [
    timeseries("Events raised", [("sum by (kind) (increase(frostbite_notify_events_total[$__rate_interval]))", "{{kind}}")], w=8, bars=True, fill=60, line=0, stack=True),
    timeseries("Deliveries", [("sum by (channel, result) (increase(frostbite_notify_deliveries_total[$__rate_interval]))", "{{channel}} {{result}}")], w=8, bars=True, fill=60, line=0, stack=True,
               overrides=[color_override(".* error", BAD), color_override(".* ok", GOOD)]),
    timeseries("Delivery time", quantiles("frostbite_notify_delivery_duration_seconds", "channel", qs=(0.5, 0.95)), "s", w=8),
    stat("Queue", "frostbite_notify_queue_length", steps=[(None, GOOD), (50, WARN), (200, BAD)], desc="Events waiting for delivery."),
    stat("Dropped, 24 h", "sum(increase(frostbite_notify_events_dropped_total[24h]))", steps=[(None, GOOD), (1, BAD)], instant=True, desc="Dropped because the queue was full."),
    stat("Failed, 24 h", 'sum(increase(frostbite_notify_deliveries_total{result="error"}[24h]))', steps=[(None, GOOD), (1, WARN)], instant=True),
    stat("Webhook retries, 24 h", "sum(increase(frostbite_notify_webhook_retries_total[24h]))", steps=[(None, GOOD), (5, WARN)], instant=True),
    stat("Bot messages, 24 h", "sum(increase(frostbite_telegram_bot_updates_total[24h]))", fixed="#7AA2F7", instant=True),
    stat("Alerts remembered", "sum(frostbite_notification_log_entries)", fixed="#7AA2F7", desc="Entries in the log that stops the same alert going out twice, kept for 90 days."),
    timeseries("Telegram API calls", [("sum by (method, result) (rate(frostbite_telegram_api_calls_total[$__rate_interval]))", "{{method}} {{result}}")], "ops", w=8,
               desc="getUpdates is the bot's long poll and runs all the time while the bot is on."),
    timeseries("Telegram call time", quantiles("frostbite_telegram_api_call_duration_seconds", "method", qs=(0.5, 0.95)), "s", w=8),
    timeseries("Bot commands", [("sum by (scope) (increase(frostbite_telegram_bot_commands_total[$__rate_interval]))", "{{scope}}")], w=8, bars=True, fill=60, line=0),
    bargauge("Alerts sent, kept 90 days", [("frostbite_notification_log_entries", "{{kind}}")], w=12, colour="#7AA2F7"),
    table("Newest alert by kind", [("frostbite_notification_log_last_timestamp_seconds * 1000", "")], w=12, h=7, rename={"Value": "Last sent", "kind": "Kind"},
          mappings={"Last sent": [{"id": "unit", "value": "dateTimeFromNow"}]}, sort=("Last sent", True)),
])

# ----- http ----------------------------------------------------------------------------------------------------------
REQ = "frostbite_http_requests_total"
row("Panel API and subscriptions", False, [
    stat("Requests per second", f"sum(rate({REQ}[$__rate_interval]))", "reqps", fixed="#7AA2F7", decimals=2),
    stat("5xx share", f'sum(rate({REQ}{{code=~"5.."}}[$__rate_interval])) / clamp_min(sum(rate({REQ}[$__rate_interval])), 0.001)', "percentunit", steps=[(None, GOOD), (0.01, WARN), (0.05, BAD)], decimals=2),
    stat("In flight", "frostbite_http_requests_in_flight", fixed="#7AA2F7", desc="Requests being handled right now, not counting daemon links."),
    stat("p95 latency", "histogram_quantile(0.95, sum by (le) (rate(frostbite_http_request_duration_seconds_bucket[$__rate_interval])))", "s", steps=[(None, GOOD), (0.5, WARN), (2, BAD)], decimals=3),
    stat("Sessions", "frostbite_sessions_active", fixed="#7AA2F7", desc="Signed in browsers across all administrators."),
    stat("Panics", f"sum(increase(frostbite_http_panics_total[$__range]))", steps=[(None, GOOD), (1, BAD)], instant=True, desc="Handlers that crashed in the selected time range."),
    timeseries("Requests by status", [(f'sum by (code) (rate({REQ}[$__rate_interval]))', "{{code}}")], "reqps", w=12, stack=True, fill=40,
               overrides=[color_override("2..", GOOD), color_override("3..", DOWN), color_override("4..", WARN), color_override("5..", BAD)]),
    timeseries("Latency", quantiles("frostbite_http_request_duration_seconds"), "s", w=12, desc="Of all requests except long lived connections."),
    heatmap("Latency distribution", "sum by (le) (rate(frostbite_http_request_duration_seconds_bucket[$__rate_interval]))", w=12),
    timeseries("Busiest routes", [(f"topk(10, sum by (route) (rate({REQ}[$__rate_interval])))", "{{route}}")], "reqps", w=12, table_legend=True),
    timeseries("Slowest routes, p95", [("topk(10, histogram_quantile(0.95, sum by (le, route) (rate(frostbite_http_request_duration_seconds_bucket[$__rate_interval]))))", "{{route}}")], "s", w=12, table_legend=True),
    timeseries("Failing routes", [(f'topk(10, sum by (route, code) (rate({REQ}{{code=~"4..|5.."}}[$__rate_interval])))', "{{route}} {{code}}")], "reqps", w=12, table_legend=True),
    timeseries("Bytes served", [("sum(rate(frostbite_http_response_bytes_total[$__rate_interval]))", "responses"), ("sum(rate(frostbite_http_request_bytes_total[$__rate_interval]))", "request bodies")], "Bps", w=12),
    timeseries("Sign ins", [("sum by (result) (increase(frostbite_auth_logins_total[$__rate_interval]))", "{{result}}")], w=8, bars=True, fill=60, line=0, stack=True,
               overrides=[color_override("success", GOOD), color_override("wrong_password|unknown_user|disabled", BAD)]),
    timeseries("Refused credentials", [("sum by (credential) (increase(frostbite_auth_rejected_requests_total[$__rate_interval]))", "{{credential}}")], w=8, bars=True, fill=60, line=0, stack=True,
               desc="Requests that arrived without a valid session ('none' is a browser that is not signed in) or with a bad API token."),
    timeseries("API token requests", [("sum(rate(frostbite_auth_api_token_requests_total[$__rate_interval]))", "requests")], "reqps", w=8),
    timeseries("Subscription downloads", [("sum by (format, result) (rate(frostbite_subscription_requests_total[$__rate_interval]))", "{{format}} {{result}}")], "reqps", w=12, stack=True, fill=40,
               desc="'auto' picks the format from the client's user agent."),
    timeseries("Subscription render time", quantiles("frostbite_subscription_render_duration_seconds", "format", qs=(0.5, 0.95)), "s", w=12),
    pie("Subscription formats, range", [("sum by (format) (increase(frostbite_subscription_requests_total{result=\"ok\"}[$__range]))", "{{format}}")], w=6),
    timeseries("Subscription size", [("sum(rate(frostbite_subscription_bytes_total[$__rate_interval]))", "served")], "Bps", w=6),
    timeseries("Device checks", [("sum by (result) (increase(frostbite_device_checks_total[$__rate_interval]))", "{{result}}")], w=6, bars=True, fill=60, line=0, stack=True,
               overrides=[color_override("limit_reached", BAD), color_override("allowed", GOOD)]),
    timeseries("User page loads", [("sum by (result) (increase(frostbite_portal_requests_total[$__rate_interval]))", "{{result}}")], w=6, bars=True, fill=60, line=0, stack=True),
    timeseries("Administrator actions", [("sum by (action) (increase(frostbite_audit_events_total[$__rate_interval]))", "{{action}}")], w=12, bars=True, fill=60, line=0, stack=True,
               desc="Everything that lands in the audit log, as it happens."),
    bargauge("Audit log, last 24 h", [("sort_desc(frostbite_audit_log_actions_24h)", "{{action}}")], w=12, colour="#7AA2F7"),
])

# ----- database ------------------------------------------------------------------------------------------------------
row("Database", True, [
    stat("Database size", "frostbite_postgres_database_size_bytes", "bytes", fixed="#7AA2F7"),
    stat("Connections", "frostbite_postgres_backends", fixed="#7AA2F7"),
    stat("Pool in use", 'frostbite_db_pool_connections{state="acquired"} / on() frostbite_db_pool_max_connections', "percentunit", steps=[(None, GOOD), (0.7, WARN), (0.9, BAD)]),
    stat("Cache hit ratio", "rate(frostbite_postgres_blocks_hit_total[$__rate_interval]) / clamp_min(rate(frostbite_postgres_blocks_hit_total[$__rate_interval]) + rate(frostbite_postgres_blocks_read_total[$__rate_interval]), 1)",
         "percentunit", steps=[(None, BAD), (0.9, WARN), (0.99, GOOD)], decimals=2),
    stat("Rolled back", "rate(frostbite_postgres_transactions_rolled_back_total[$__rate_interval]) / clamp_min(rate(frostbite_postgres_transactions_committed_total[$__rate_interval]) + rate(frostbite_postgres_transactions_rolled_back_total[$__rate_interval]), 0.001)",
         "percentunit", steps=[(None, GOOD), (0.05, WARN)], decimals=2),
    stat("Deadlocks", "increase(frostbite_postgres_deadlocks_total[$__range])", steps=[(None, GOOD), (1, BAD)], instant=True),
    timeseries("Query rate", [("topk(10, sum by (query) (rate(frostbite_db_queries_total[$__rate_interval])))", "{{query}}")], "ops", w=12, table_legend=True),
    timeseries("Query time, p95", [("topk(10, histogram_quantile(0.95, sum by (le, query) (rate(frostbite_db_query_duration_seconds_bucket[$__rate_interval]))))", "{{query}}")], "s", w=12, table_legend=True,
               desc="Per sqlc query. Hand written queries are grouped as 'other'."),
    timeseries("Query errors", [('sum by (query) (increase(frostbite_db_queries_total{result="error"}[$__rate_interval]))', "{{query}}")], w=8, bars=True, fill=60, line=0, stack=True),
    timeseries("Query time overall", quantiles("frostbite_db_query_duration_seconds"), "s", w=8),
    timeseries("Pool connections", [("frostbite_db_pool_connections", "{{state}}"), ("frostbite_db_pool_max_connections", "limit")], w=8),
    timeseries("Waiting for a connection", [("rate(frostbite_db_pool_acquire_seconds_total[$__rate_interval])", "seconds waited per second"), ("rate(frostbite_db_pool_empty_acquires_total[$__rate_interval])", "acquires that had to wait")], w=8,
               desc="Should hug zero. If not, queries queue for a connection."),
    timeseries("Server connections", [("frostbite_postgres_connections", "{{state}}"), ("frostbite_postgres_max_connections", "limit")], w=8),
    timeseries("Transactions", [("rate(frostbite_postgres_transactions_committed_total[$__rate_interval])", "committed"), ("rate(frostbite_postgres_transactions_rolled_back_total[$__rate_interval])", "rolled back")], "ops", w=8,
               overrides=[color_override("rolled back", BAD)]),
    timeseries("Rows", [("rate(frostbite_postgres_tuples_inserted_total[$__rate_interval])", "inserted"), ("rate(frostbite_postgres_tuples_updated_total[$__rate_interval])", "updated"), ("rate(frostbite_postgres_tuples_deleted_total[$__rate_interval])", "deleted"),
                        ("rate(frostbite_postgres_tuples_fetched_total[$__rate_interval])", "fetched by index"), ("rate(frostbite_postgres_tuples_returned_total[$__rate_interval])", "returned by scans")], "ops", w=8),
    timeseries("Locks and long transactions", [("frostbite_postgres_locks_waiting", "locks waiting"), ("frostbite_postgres_longest_transaction_seconds", "longest transaction (s)")], w=8),
    timeseries("Temp files", [("rate(frostbite_postgres_temp_bytes_total[$__rate_interval])", "bytes written")], "Bps", w=8),
    bargauge("Table size", [("sort_desc(frostbite_postgres_table_size_bytes)", "{{table}}")], "bytes", w=8, h=10, colour="#7AA2F7", desc="Including indexes."),
    bargauge("Table rows", [("sort_desc(frostbite_postgres_table_rows)", "{{table}}")], "short", w=8, h=10, colour="#7AA2F7", desc="Estimated from statistics."),
    bargauge("Dead rows", [("sort_desc(frostbite_postgres_table_dead_rows)", "{{table}}")], "short", w=8, h=10, colour=WARN, desc="Waiting for vacuum."),
    timeseries("Database size", [("frostbite_postgres_database_size_bytes", "total"), ("sum(frostbite_postgres_table_size_bytes)", "tables")], "bytes", w=8),
    timeseries("Hourly traffic table", [("frostbite_traffic_history_rows", "rows")], w=8, desc="One row per user, node and hour. Pruned after 400 days."),
    timeseries("Metric refresh time", [("frostbite_collect_duration_seconds", "{{group}}")], "s", w=8, desc="How long the database queries behind this dashboard take. They run at most every 10 seconds."),
    timeseries("Metric refresh failures", [("sum by (group) (increase(frostbite_collect_failures_total[$__rate_interval]))", "{{group}}")], w=8, bars=True, fill=60, line=0),
    timeseries("Metric age", [("time() - frostbite_collect_last_success_timestamp_seconds", "{{group}}")], "s", w=8, desc="Seconds since each group of database metrics last refreshed successfully."),
])

# ----- panel runtime -------------------------------------------------------------------------------------------------
row("Panel process", True, [
    stat("Goroutines", "go_goroutines{job=\"frostbite\"}", fixed="#7AA2F7"),
    stat("Memory (RSS)", "frostbite_process_resident_memory_bytes", "bytes", fixed="#7AA2F7"),
    stat("Heap in use", "go_memstats_heap_inuse_bytes{job=\"frostbite\"}", "bytes", fixed="#7AA2F7"),
    stat("Open files", "frostbite_process_open_fds", fixed="#7AA2F7"),
    stat("Threads", "go_threads{job=\"frostbite\"}", fixed="#7AA2F7"),
    stat("Go", "frostbite_build_info", text="name", fixed=MUTED, spark=False, instant=True, color="none") | {"targets": [tgt("frostbite_build_info", "{{go_version}} {{goos}}/{{goarch}}", instant=True)]},
    timeseries("Memory", [("frostbite_process_resident_memory_bytes", "resident"), ("go_memstats_heap_inuse_bytes{job=\"frostbite\"}", "heap in use"), ("go_memstats_stack_inuse_bytes{job=\"frostbite\"}", "stacks"),
                          ("go_memstats_sys_bytes{job=\"frostbite\"}", "obtained from the system")], "bytes", w=8),
    timeseries("CPU", [("rate(frostbite_process_cpu_seconds_total[$__rate_interval])", "cores used")], w=8, desc="1 means one full core."),
    timeseries("Goroutines and threads", [("go_goroutines{job=\"frostbite\"}", "goroutines"), ("go_threads{job=\"frostbite\"}", "threads")], w=8),
    timeseries("Garbage collection", [("rate(go_gc_duration_seconds_count{job=\"frostbite\"}[$__rate_interval])", "cycles per second")], w=8),
    timeseries("GC pause", [("rate(go_gc_duration_seconds_sum{job=\"frostbite\"}[$__rate_interval]) / rate(go_gc_duration_seconds_count{job=\"frostbite\"}[$__rate_interval])", "average"), ("go_gc_duration_seconds{job=\"frostbite\",quantile=\"1\"}", "longest so far")], "s", w=8),
    timeseries("Allocation rate", [("rate(go_memstats_alloc_bytes_total{job=\"frostbite\"}[$__rate_interval])", "allocated")], "Bps", w=8),
    timeseries("File descriptors", [("frostbite_process_open_fds", "open"), ("frostbite_process_max_fds", "limit")], w=8),
    timeseries("Network of the panel process", [("rate(frostbite_process_network_receive_bytes_total[$__rate_interval])", "received"), ("rate(frostbite_process_network_transmit_bytes_total[$__rate_interval])", "sent")], "Bps", w=8),
    timeseries("Scrape time", [('scrape_duration_seconds{job="frostbite"}', "scrape")], "s", w=4, desc="How long Prometheus waits for /metrics. Mostly the database queries, which are cached for 10 seconds."),
    timeseries("Series exposed", [('scrape_samples_scraped{job="frostbite"}', "series")], w=4, desc="Grows with users when per-user metrics are on, and with nodes and inbounds."),
])

# ----- panel host ----------------------------------------------------------------------------------------------------
row("Panel host", True, [
    text("", "Needs the `node-exporter` service of the monitoring profile. Nodes report their own health under *Nodes and daemons*.", h=2),
    gauge("CPU", '1 - avg(rate(node_cpu_seconds_total{mode="idle"}[$__rate_interval]))', w=4),
    gauge("Memory", "1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes", w=4),
    gauge("Disk /", '1 - node_filesystem_avail_bytes{mountpoint="/",fstype!="rootfs"} / node_filesystem_size_bytes{mountpoint="/",fstype!="rootfs"}', w=4),
    stat("Uptime", "time() - node_boot_time_seconds", "s", fixed="#7AA2F7", instant=True),
    stat("Load (1 m)", "node_load1", fixed="#7AA2F7", decimals=2),
    stat("CPU cores", 'count(node_cpu_seconds_total{mode="idle"})', fixed="#7AA2F7", instant=True),
    timeseries("CPU", [('sum by (mode) (rate(node_cpu_seconds_total{mode!="idle"}[$__rate_interval])) / on() group_left() count(node_cpu_seconds_total{mode="idle"})', "{{mode}}")], "percentunit", w=8, stack=True, fill=40, lo=0),
    timeseries("Memory", [("node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes", "used"), ("node_memory_Cached_bytes", "cache"), ("node_memory_SwapTotal_bytes - node_memory_SwapFree_bytes", "swap used")], "bytes", w=8),
    timeseries("Network", [('sum(rate(node_network_receive_bytes_total{device!~"lo|veth.*|docker.*|br-.*"}[$__rate_interval]))', "in"),
                           ('sum(rate(node_network_transmit_bytes_total{device!~"lo|veth.*|docker.*|br-.*"}[$__rate_interval]))', "out")], "Bps", w=8,
               overrides=[color_override("in", DOWN), color_override("out", UP)], desc="Physical interfaces only, so traffic through docker bridges is not counted twice."),
    timeseries("Disk throughput", [('sum(rate(node_disk_read_bytes_total[$__rate_interval]))', "read"), ('sum(rate(node_disk_written_bytes_total[$__rate_interval]))', "written")], "Bps", w=8),
    timeseries("Filesystem free", [('node_filesystem_avail_bytes{fstype!~"tmpfs|overlay|squashfs|rootfs"} / node_filesystem_size_bytes{fstype!~"tmpfs|overlay|squashfs|rootfs"}', "{{mountpoint}}")], "percentunit", w=8, lo=0, hi=1),
    timeseries("Load average", [("node_load1", "1 m"), ("node_load5", "5 m"), ("node_load15", "15 m")], w=8),
])

# ----- backups -------------------------------------------------------------------------------------------------------
row("Backups", True, [
    stat("Newest backup", "time() - frostbite_backup_latest_timestamp_seconds", "s", steps=[(None, GOOD), (86400 * 2, WARN), (86400 * 7, BAD)], desc="Age of the newest file.", instant=True),
    stat("Backup size", "frostbite_backup_latest_bytes", "bytes", fixed="#7AA2F7"),
    stat("Files kept", "frostbite_backup_files", fixed="#7AA2F7"),
    stat("Space used", "frostbite_backup_files_bytes", "bytes", fixed="#7AA2F7"),
    stat("Every", "frostbite_backup_schedule_interval_seconds", "s", fixed=MUTED, spark=False),
    stat("Keep", "frostbite_backup_schedule_keep", fixed=MUTED, spark=False),
    timeseries("Backups made", [("sum by (trigger, result) (increase(frostbite_backup_runs_total[$__rate_interval]))", "{{trigger}} {{result}}")], w=8, bars=True, fill=60, line=0, stack=True,
               overrides=[color_override(".* error", BAD)]),
    timeseries("Backup time", [("histogram_quantile(0.95, sum by (le, trigger) (rate(frostbite_backup_duration_seconds_bucket[1h])))", "{{trigger}} p95")], "s", w=8),
    timeseries("Backup size over time", [("frostbite_backup_latest_bytes", "newest file"), ("frostbite_backup_files_bytes", "all files")], "bytes", w=8),
    timeseries("Imports", [("sum by (source, result) (increase(frostbite_import_runs_total[$__rate_interval]))", "{{source}} {{result}}"), ("sum by (outcome) (increase(frostbite_import_users_total[$__rate_interval]))", "users {{outcome}}")], w=12, bars=True, fill=60, line=0),
    timeseries("WARP", [("sum by (op, result) (increase(frostbite_warp_operations_total[$__rate_interval]))", "{{op}} {{result}}")], w=12, bars=True, fill=60, line=0),
])

# ---------------------------------------------------------------------------------------------------------------------

def layout(panels, y0):
    """flows panels left to right, wrapping at 24 columns, and returns the next free y"""
    x, y, tallest = 0, y0, 0
    for p in panels:
        w, h = p["gridPos"]["w"], p["gridPos"]["h"]
        if x + w > 24:
            x, y, tallest = 0, y + tallest, 0
        p["gridPos"] = {"x": x, "y": y, "w": w, "h": h}
        x += w
        tallest = max(tallest, h)
    return y + tallest

out, y = [], 0
for title, collapsed, panels in rows:
    r = {"id": nid(), "type": "row", "title": title, "collapsed": collapsed, "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}, "panels": []}
    end = layout(panels, y + 1)
    if collapsed:
        r["panels"] = panels
        out.append(r)
        y += 1
    else:
        out.append(r)
        out.extend(panels)
        y = end

def var_query(name, label, query, include_all=True):
    return {
        "name": name, "label": label, "type": "query", "datasource": DS, "multi": True, "includeAll": include_all, "allValue": ".*",
        "current": {"selected": True, "text": ["All"], "value": ["$__all"]}, "refresh": 2, "sort": 1,
        "query": {"query": query, "refId": "var"}, "definition": query, "regex": "", "skipUrlSync": False,
    }

dashboard = {
    "uid": "frostbite", "title": "Frostbite", "tags": ["frostbite", "vpn"], "timezone": "browser", "editable": True, "graphTooltip": 1,
    "schemaVersion": 39, "version": 1, "refresh": "30s", "time": {"from": "now-6h", "to": "now"}, "timepicker": {"refresh_intervals": ["10s", "30s", "1m", "5m", "15m", "1h"]},
    "fiscalYearStartMonth": 0, "liveNow": False, "weekStart": "monday",
    "annotations": {"list": [{
        "builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"}, "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)", "name": "Annotations & Alerts", "type": "dashboard",
    }, {
        "datasource": DS, "enable": True, "iconColor": "#E5534B", "name": "Daemon reconnects", "expr": 'increase(frostbite_link_connections_total[1m]) > 0',
        "titleFormat": "{{kind}} daemon connected", "step": "1m", "hide": True,
    }]},
    "templating": {"list": [
        var_query("node", "Node", "label_values(frostbite_node_info, node)"),
        var_query("daemon", "Daemon", 'label_values(frostbite_daemon_info{node=~"$node"}, daemon)'),
    ]},
    "links": [{"title": "Prometheus", "type": "link", "url": "http://127.0.0.1:9090", "targetBlank": True, "icon": "external link"}],
    "panels": out,
}

path = pathlib.Path(__file__).parent / "dashboards" / "frostbite.json"
path.write_text(json.dumps(dashboard, indent=1, ensure_ascii=False) + "\n")
n = sum(1 for p in out if p["type"] != "row") + sum(len(p["panels"]) for p in out if p["type"] == "row")
print(f"wrote {path} with {n} panels")
