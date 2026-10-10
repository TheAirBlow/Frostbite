# TODO

Done: panel, Xray / sing-box / edge daemons, nodes, inbounds, hosts, squads and plans, users with limits / resets / on-hold / device and IP limits, relay and chain bridges, routing, subscriptions (links, Clash, sing-box, Xray), user page, admin roles, resellers with quotas, WireGuard, automatic certificates, WARP, Telegram bot, webhooks, backups, CSV/JSON import and native 3x-ui / Marzban / Hiddify database import, i18n (en, ru, fa, zh) of all screens, user page branding (logo, accent, footer), live user updates for most sing-box protocols, ShadowTLS client profiles (sing-box and Clash), MTProto daemon with one secret per user, Turnable daemon.

## Not done yet
- MTProto: only tested against a client written for the tests and the panel round trip. Fake TLS, secrets and relaying work there, but a real Telegram client has not been tried; it connects straight to Telegram's data centers, with no ad tag
- DNS tunnel daemons (dnstt, slipstream): no per-user accounting is possible and clients have no share link format, so there is little for the panel to manage
- Turnable: never run against a real VK call, and no Turnable client has tried the panel's links beyond parsing them. Only relay mode on VK exists, and a captcha that cannot be solved automatically needs a manual solve on port 1984 of the node
- PROXY protocol for sing-box inbounds behind an edge (upstream removed it)
- SSH client profiles (there is no SSH server in the panel)
- WireGuard for Xray: its WireGuard inbound reports no per-user traffic, so quotas would not work
- Publishing the Docker images (the workflow in .github/workflows/images.yml is untested, nothing could run Docker here)
