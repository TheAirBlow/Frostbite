# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Two audiences carry equal weight in the admin panel:

- Technical self-hosters running a VPN for themselves, friends and family on a few servers.
- Small VPN operators running a paid or semi-public service, with resellers, quotas and many end users.

Both are comfortable with servers, protocols and Docker. They use the panel to add nodes and daemons, build inbounds, group them into squads and plans, manage users, and hand out subscriptions.

End users of the `/u/<token>` page are a third audience. The page has to work for non-technical people on a phone who only want a QR code or a link, and also for technical users who want raw links and specific formats.

## Product Purpose

Frostbite is a VPN management panel. It holds users, nodes, inbounds, routing and subscriptions, pushes config to per-core daemons, and collects their usage. Success means an operator can stand up and run a censorship-resistant service across many servers without hand-editing core configs, and their users can connect without help.

## Positioning

- Servers and the panel don't depend on each other. Each core runs as its own small daemon that dials the panel, gets its config pushed and reports usage back. A node can run any mix of daemons.
- Bridges are first class. A relay forwards raw traffic to an inbound, and a chain exits through another server or any proxy from a share link. The panel shows a map of how servers connect.
- It covers cores other panels skip: an MTProto daemon with a secret per user, Turnable (tunnels inside a VK call), an edge daemon that shares one port by TLS server name, and a guard that keeps a real site reachable when the core fails.
- It is built for hostile networks, with REALITY, decoys, fake TLS and WARP exits. The UI is in four languages: en, ru, fa and zh.

## Operating Context

- The panel (Go + Postgres) has no published port. The Nuxt frontend is the only public service and proxies `/api`, `/sub`, `/node` and the daemon websocket.
- Operators work per server: add a node, add a daemon, then run the one-line command the panel shows on that server.
- Optional Prometheus metrics come with a generated Grafana dashboard.
- Operators often migrate from Hiddify, Marzban, 3x-ui or Remnawave through the CSV/JSON or database import.

## Capabilities and Constraints

- Admin sections: nodes, inbounds, bridges, routing, subscriptions, users, and access (admins, roles, resellers).
- Protocols: VLESS (Reality, XHTTP, WS, gRPC, HTTPUpgrade), VMess, Trojan, Shadowsocks 2022, Hysteria2, TUIC, AnyTLS, Naive, SOCKS/HTTP and WireGuard.
- Subscription formats: share links, Clash, sing-box and Xray, with per-client rules and templates.
- Alerts go to Telegram (admin alerts, user alerts, a bot) and to signed webhooks. Backups are a single JSON file.
- The stack is fixed: Nuxt 4 with Tailwind and daisyUI, server rendered.
- Every screen must work in all four locales, including right-to-left Farsi.
- Several features are untested against real clients, and [the TODO list](TODO.md) records them. The UI must not imply they are proven.

## Brand Commitments

- The name is Frostbite.
- Operators can brand the user page with their own logo, accent color and footer, so that page has to carry someone else's identity cleanly.

## Evidence on Hand

- Product description and setup flow: [the README](README.md).
- Feature status and known gaps: [the TODO list](TODO.md).
- There are no testimonials, customer names, user counts or benchmarks. Do not invent any.

## Product Principles

1. Operators are experts, so don't hide protocol detail from them. Make it fast to scan and hard to misconfigure.
2. The panel shows real state. Daemon link status, config revisions, errors and certificate state are shown as they are and never smoothed over.
3. The user page is for someone who just wants to connect. The simple path comes first and the raw detail stays one step away.
4. Every screen works in every locale, right-to-left layout included.
5. Never claim more than is tested.

## Accessibility & Inclusion

Four locales (en, ru, fa, zh), with right-to-left layout for Farsi. The user page has to work on phones for non-technical users.
