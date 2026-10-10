-- +goose Up

CREATE TABLE admins (
    id             BIGSERIAL PRIMARY KEY,
    username       TEXT NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9_.-]{2,32}$'),
    password_hash  TEXT NOT NULL,
    role           TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('owner', 'admin', 'reseller')),
    enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    user_quota     INTEGER,
    traffic_quota  BIGINT,
    note           TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id          BIGSERIAL PRIMARY KEY,
    admin_id    BIGINT NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    user_agent  TEXT NOT NULL DEFAULT '',
    ip          TEXT NOT NULL DEFAULT '',
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE api_tokens (
    id            BIGSERIAL PRIMARY KEY,
    admin_id      BIGINT NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    token_hash    TEXT NOT NULL UNIQUE,
    last_used_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
    id          BIGSERIAL PRIMARY KEY,
    admin_id    BIGINT REFERENCES admins (id) ON DELETE SET NULL,
    admin_name  TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,
    target      TEXT NOT NULL DEFAULT '',
    detail      JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_created_idx ON audit_log (created_at DESC);

CREATE TABLE settings (
    key    TEXT PRIMARY KEY,
    value  JSONB NOT NULL
);

CREATE TABLE nodes (
    id                  BIGSERIAL PRIMARY KEY,
    name                TEXT NOT NULL,
    address             TEXT NOT NULL,
    country             TEXT NOT NULL DEFAULT '',
    tags                TEXT[] NOT NULL DEFAULT '{}',
    traffic_multiplier  DOUBLE PRECISION NOT NULL DEFAULT 1 CHECK (traffic_multiplier >= 0),
    traffic_limit       BIGINT NOT NULL DEFAULT 0,
    traffic_used        BIGINT NOT NULL DEFAULT 0,
    note                TEXT NOT NULL DEFAULT '',
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    sort                INTEGER NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE daemons (
    id             BIGSERIAL PRIMARY KEY,
    node_id        BIGINT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    kind           TEXT NOT NULL,
    name           TEXT NOT NULL,
    token_hash     TEXT NOT NULL UNIQUE,
    enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    desired_rev    BIGINT NOT NULL DEFAULT 0,
    applied_rev    BIGINT NOT NULL DEFAULT 0,
    spec_hash      TEXT NOT NULL DEFAULT '',
    last_error     TEXT NOT NULL DEFAULT '',
    last_seen      TIMESTAMPTZ,
    core_version   TEXT NOT NULL DEFAULT '',
    agent_version  TEXT NOT NULL DEFAULT '',
    host_info      JSONB NOT NULL DEFAULT '{}',
    log_level      TEXT NOT NULL DEFAULT 'warning',
    dns_servers    TEXT[] NOT NULL DEFAULT '{1.1.1.1,8.8.8.8}',
    dns_strategy   TEXT NOT NULL DEFAULT 'prefer_ipv4',
    final_outbound TEXT NOT NULL DEFAULT 'direct',
    raw_patch      JSONB,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX daemons_node_idx ON daemons (node_id);

CREATE TABLE inbounds (
    id          BIGSERIAL PRIMARY KEY,
    daemon_id   BIGINT NOT NULL REFERENCES daemons (id) ON DELETE CASCADE,
    tag         TEXT NOT NULL,
    remark      TEXT NOT NULL DEFAULT '',
    protocol    TEXT NOT NULL,
    listen      TEXT NOT NULL DEFAULT '',
    port        INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    transport   JSONB NOT NULL DEFAULT '{}',
    security    JSONB NOT NULL DEFAULT '{}',
    options     JSONB NOT NULL DEFAULT '{}',
    sniffing    JSONB NOT NULL DEFAULT '{}',
    forward     JSONB,
    raw_patch   JSONB,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    system      BOOLEAN NOT NULL DEFAULT FALSE,
    sort        INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (daemon_id, tag)
);

CREATE TABLE hosts (
    id                 BIGSERIAL PRIMARY KEY,
    inbound_id         BIGINT NOT NULL REFERENCES inbounds (id) ON DELETE CASCADE,
    bridge_inbound_id  BIGINT REFERENCES inbounds (id) ON DELETE CASCADE,
    remark             TEXT NOT NULL DEFAULT '{node} {protocol}',
    address            TEXT NOT NULL DEFAULT '',
    port               INTEGER,
    sni                TEXT NOT NULL DEFAULT '',
    host               TEXT NOT NULL DEFAULT '',
    path               TEXT NOT NULL DEFAULT '',
    alpn               TEXT[] NOT NULL DEFAULT '{}',
    fingerprint        TEXT NOT NULL DEFAULT '',
    insecure           BOOLEAN NOT NULL DEFAULT FALSE,
    mux                JSONB,
    fragment           JSONB,
    enabled            BOOLEAN NOT NULL DEFAULT TRUE,
    sort               INTEGER NOT NULL DEFAULT 0,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX hosts_inbound_idx ON hosts (inbound_id);

CREATE TABLE outbounds (
    id                BIGSERIAL PRIMARY KEY,
    daemon_id         BIGINT NOT NULL REFERENCES daemons (id) ON DELETE CASCADE,
    tag               TEXT NOT NULL,
    kind              TEXT NOT NULL CHECK (kind IN ('direct', 'block', 'proxy', 'warp')),
    upstream          JSONB,
    target_inbound_id BIGINT REFERENCES inbounds (id) ON DELETE CASCADE,
    interface         TEXT NOT NULL DEFAULT '',
    strategy          TEXT NOT NULL DEFAULT '',
    sort              INTEGER NOT NULL DEFAULT 0,
    UNIQUE (daemon_id, tag)
);

CREATE TABLE rules (
    id        BIGSERIAL PRIMARY KEY,
    daemon_id BIGINT REFERENCES daemons (id) ON DELETE CASCADE,
    name      TEXT NOT NULL DEFAULT '',
    match     JSONB NOT NULL DEFAULT '{}',
    outbound  TEXT NOT NULL,
    enabled   BOOLEAN NOT NULL DEFAULT TRUE,
    sort      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE squads (
    id    BIGSERIAL PRIMARY KEY,
    name  TEXT NOT NULL UNIQUE,
    note  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE squad_inbounds (
    squad_id    BIGINT NOT NULL REFERENCES squads (id) ON DELETE CASCADE,
    inbound_id  BIGINT NOT NULL REFERENCES inbounds (id) ON DELETE CASCADE,
    PRIMARY KEY (squad_id, inbound_id)
);

CREATE TABLE plans (
    id                  BIGSERIAL PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE,
    traffic_limit       BIGINT NOT NULL DEFAULT 0,
    duration_days       INTEGER NOT NULL DEFAULT 0,
    reset_strategy      TEXT NOT NULL DEFAULT 'none' CHECK (reset_strategy IN ('none', 'day', 'week', 'month', 'year')),
    start_on_first_use  BOOLEAN NOT NULL DEFAULT FALSE,
    device_limit        INTEGER NOT NULL DEFAULT 0,
    ip_limit            INTEGER NOT NULL DEFAULT 0,
    squad_ids           BIGINT[] NOT NULL DEFAULT '{}',
    note                TEXT NOT NULL DEFAULT ''
);

CREATE TABLE users (
    id                BIGSERIAL PRIMARY KEY,
    username          TEXT NOT NULL UNIQUE CHECK (username ~ '^[A-Za-z0-9_.@-]{2,64}$'),
    uuid              UUID NOT NULL UNIQUE,
    password          TEXT NOT NULL,
    sub_token         TEXT NOT NULL UNIQUE,
    status            TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'limited', 'expired', 'on_hold')),
    traffic_limit     BIGINT NOT NULL DEFAULT 0,
    traffic_used      BIGINT NOT NULL DEFAULT 0,
    traffic_lifetime  BIGINT NOT NULL DEFAULT 0,
    reset_strategy    TEXT NOT NULL DEFAULT 'none' CHECK (reset_strategy IN ('none', 'day', 'week', 'month', 'year')),
    last_reset        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expire_at         TIMESTAMPTZ,
    on_hold_days      INTEGER NOT NULL DEFAULT 0,
    device_limit      INTEGER NOT NULL DEFAULT 0,
    ip_limit          INTEGER NOT NULL DEFAULT 0,
    tags              TEXT[] NOT NULL DEFAULT '{}',
    note              TEXT NOT NULL DEFAULT '',
    email             TEXT NOT NULL DEFAULT '',
    telegram_id       BIGINT,
    plan_id           BIGINT REFERENCES plans (id) ON DELETE SET NULL,
    owner_id          BIGINT REFERENCES admins (id) ON DELETE SET NULL,
    online_at         TIMESTAMPTZ,
    blocked_until     TIMESTAMPTZ,
    sub_last_at       TIMESTAMPTZ,
    sub_last_ua       TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX users_status_idx ON users (status);
CREATE INDEX users_owner_idx ON users (owner_id);

CREATE TABLE user_squads (
    user_id   BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    squad_id  BIGINT NOT NULL REFERENCES squads (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, squad_id)
);

CREATE TABLE user_devices (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    hwid        TEXT NOT NULL,
    platform    TEXT NOT NULL DEFAULT '',
    model       TEXT NOT NULL DEFAULT '',
    os_version  TEXT NOT NULL DEFAULT '',
    user_agent  TEXT NOT NULL DEFAULT '',
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, hwid)
);

CREATE TABLE traffic_hourly (
    user_id  BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    node_id  BIGINT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    hour     TIMESTAMPTZ NOT NULL,
    up       BIGINT NOT NULL DEFAULT 0,
    down     BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, node_id, hour)
);

CREATE INDEX traffic_hourly_hour_idx ON traffic_hourly (hour);

CREATE TABLE sub_templates (
    id      BIGSERIAL PRIMARY KEY,
    name    TEXT NOT NULL UNIQUE,
    format  TEXT NOT NULL,
    patch   JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE sub_rules (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL DEFAULT '',
    ua_regex     TEXT NOT NULL,
    format       TEXT NOT NULL,
    template_id  BIGINT REFERENCES sub_templates (id) ON DELETE SET NULL,
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    sort         INTEGER NOT NULL DEFAULT 0
);

-- +goose Down

DROP TABLE sub_rules, sub_templates, traffic_hourly, user_devices, user_squads, users, plans, squad_inbounds, squads,
    rules, outbounds, hosts, inbounds, daemons, nodes, settings, audit_log, api_tokens, sessions, admins;
