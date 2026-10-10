# Frostbite

A VPN management panel built around the idea that servers and the panel should not care about each other.

- **Panel** (Go + Postgres) holds users, nodes, inbounds, routing and subscriptions, and serves the web UI.
- **Daemons** are one small binary per core (`agent-xray`, `agent-singbox`). They dial the panel, get their config pushed, and report usage back. A node can run any mix of them.
- **Bridges** are first class. A *relay* forwards raw traffic to one of your inbounds. A *chain* is a full server whose traffic leaves through another of your servers, or any proxy from a share link.
- **Frontend** is a server rendered Nuxt app (Tailwind + daisyUI) in its own container. It is the only thing that is published: it proxies `/api`, `/sub`, `/node` and the daemon websocket to the panel, which has no published port.
- **Monitoring** is optional: the panel exposes Prometheus metrics and ships a Grafana dashboard.

## Running it

```sh
cp .env.example .env        # set POSTGRES_PASSWORD at least
docker compose up -d
docker compose logs panel   # the first owner password is printed here when you did not set one
```

Open `http://localhost:8080` (the `web` service), then:

1. **Nodes -> Add node**, then **Add daemon** and pick a core. The panel shows a one line command to run on that server.
2. **Inbounds -> New inbound** and pick a recipe (VLESS Reality is a good start).
3. **Squads & plans -> New squad**, tick the inbound.
4. **Users -> New user**. Share their subscription link, or the page at `/u/<token>`.

To run a daemon on the panel's own machine, put its token in `.env` and use `docker compose --profile xray up -d`.

## Monitoring

```sh
docker compose --profile monitoring up -d     # Prometheus, Grafana and node-exporter next to the panel
```

Grafana is on `http://127.0.0.1:3000` (`admin` / `GRAFANA_PASSWORD`) with the **Frostbite** dashboard already loaded; Prometheus is on `http://127.0.0.1:9090` and evaluates the rules in `docker/alerts.yml`.

The panel serves `/metrics` on its own port (`FROSTBITE_METRICS_ADDR`, `127.0.0.1:9091` by default, `0.0.0.0:9091` inside compose, never published). Set `FROSTBITE_METRICS_TOKEN` to require a bearer token, and `FROSTBITE_METRICS_PER_USER=false` to drop the per-user series on very large installs. What it covers:

- **Users:** counts by status, plan, owner, squad, tag, reset schedule and client app; expiry and usage buckets; activity windows; devices; per-user traffic, limits, expiry and live addresses.
- **Traffic:** billed and raw throughput by node and direction, windows of 1 h to 30 d from the hourly table, node limits and multipliers.
- **Nodes and daemons:** link state, versions, configuration revisions and errors, connected users, certificates, and the health each daemon reports (CPU, memory, swap, disk and network rates, sockets, file descriptors, load).
- **Inventory:** inbounds by protocol, transport and security, hosts, outbounds, rules, plans, administrators, sessions and tokens.
- **Internals:** HTTP requests and latency by route, sign ins, subscription downloads, spec pushes and acknowledgements, quota enforcement, alert and Telegram delivery, backups, imports, WARP, Postgres and the connection pool, Go runtime.

The dashboard is generated: edit `docker/grafana/build_dashboard.py` and run it to rewrite `docker/grafana/dashboards/frostbite.json`.

## What it does

- **Cores:** Xray and sing-box daemons, an **mtproto** daemon (Telegram proxy with a secret per user, fake TLS disguise), plus an **edge** daemon that shares one public port between them by TLS server name and sends everything else to a decoy.
- **Protocols:** VLESS (Reality, XHTTP, WS, gRPC, HTTPUpgrade), VMess, Trojan, Shadowsocks 2022, Hysteria2, TUIC, AnyTLS, Naive, SOCKS/HTTP and WireGuard.
- **Bridges:** relays and chains, with a map of how your servers connect.
- **Certificates:** daemons get and renew Let's Encrypt certificates themselves, and show a self signed stand-in until the real one lands.
- **WARP:** the panel registers a Cloudflare WARP account and cores use it as a WireGuard exit. WARP+ keys are supported.
- **Users:** limits, resets, on-hold, device and IP limits, squads and plans, resellers with user and traffic quotas, CSV/JSON import from Hiddify, Marzban, 3x-ui and Remnawave exports.
- **Subscriptions:** share links, Clash, sing-box and Xray formats, per-client rules and templates, and a user page with QR codes in four languages.
- **Alerts:** Telegram (admin alerts, user alerts and a bot with commands) and signed webhooks.
- **Backups:** download, restore and scheduled, in one json file.

## Layout

```
cmd/panel, cmd/agent-xray, cmd/agent-singbox
internal/spec      the core-agnostic description of what a daemon runs
internal/core      renderers: spec -> native xray / sing-box config, behind a registry
internal/compose   database state -> one spec per daemon (squads, bridges, system users)
internal/hub       daemon links, spec pushes, usage ingest
internal/api       REST api, subscriptions, user portal
internal/share     share links and subscription formats (links, clash, sing-box, xray)
internal/agent     what every daemon shares; agent/xray and agent/singbox drive one core each
internal/quota     expiry, limits, resets, on-hold activation
internal/notify    webhooks, Telegram alerts and the bot
internal/backup    dump and restore
internal/warp      Cloudflare WARP registration
internal/importer  user lists from other panels
frontend/          the Nuxt app (server rendered, proxies to the panel)
docker/            Prometheus, alert rules and the Grafana dashboard
internal/metrics   Prometheus metrics
node/              the compose file new nodes download
```

## Adding a core

1. `internal/core/<kind>`: a package that registers a `core.Descriptor` (capabilities and a `Render` function).
2. `internal/agent/<kind>`: a `Runtime` that applies a rendered config and reports stats.
3. `cmd/agent-<kind>/main.go`, a target in `Dockerfile.agent` and a profile in `node/docker-compose.yml`.

The forms in the UI come from the spec struct tags, so nothing changes in the frontend.

## Development

```sh
sqlc generate                                   # after touching internal/db/queries or migrations
go test ./...
go run ./cmd/panel                              # needs FROSTBITE_DATABASE_URL
cd frontend && bun install && bun run dev       # proxies /api to :8080
```

The panel image is the API only and `frontend/Dockerfile` builds the web interface. Behind nginx or Caddy for TLS, have the proxy set `X-Real-IP`: the frontend trusts only that header (never `X-Forwarded-For`) for the client address.
A single binary with the UI embedded is still possible: `bun run generate` in `frontend/`, copy `.output/public` into `internal/frontend/dist` and `go build -tags frontend ./cmd/panel` (the static build needs `ssr: false` and no server routes).

Configuration is `FROSTBITE_*` environment variables (or `data/config.json`), see `internal/common/config.go`.

## Things to know

- Behind an edge daemon only Xray inbounds learn the real client address (PROXY protocol). sing-box dropped support for it, so IP limits and "connected from" are not accurate for those.
- WARP needs UDP to Cloudflare from the node. Some networks block it, in which case registration works but traffic does not flow.
- Automatic certificates use the HTTP-01 challenge, so the domain must point at the node and port 80 must be free there.
- I could not run Docker here, so the Dockerfiles and compose files were written but not built. Everything else was run for real, including the panel, the proxy (HTTP and the daemon websocket), Prometheus and Grafana as plain processes.
- Daemons now reach the panel through the web service, so `FROSTBITE_PANEL_URL` must point at the web address.

- Xray picks up user changes live. sing-box does too for VLESS, Trojan, Hysteria2, TUIC and Shadowsocks (it reaches into sing-box internals, pinned to one version, and falls back to a restart if anything looks different). WireGuard, VMess, AnyTLS and Naive still restart it. A user who loses access has their open connections on sing-box cut.
- Xray 26 removed `allowInsecure`. Nodes with self signed certificates work for sing-box clients only, so use real certificates for Xray TLS inbounds.
- Without a certificate at the configured path the daemon creates a self signed one so it can start.

## License

GNU General Public License v2.0, see [LICENSE](LICENSE).
