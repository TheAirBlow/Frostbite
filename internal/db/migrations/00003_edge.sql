-- +goose Up

ALTER TABLE daemons
    ADD COLUMN edge_listen   TEXT[] NOT NULL DEFAULT '{:443}',
    ADD COLUMN edge_default  TEXT NOT NULL DEFAULT '';

-- An inbound can sit behind an edge daemon on the same node, which then shares its public port with others by server name.
ALTER TABLE inbounds
    ADD COLUMN edge_daemon_id  BIGINT REFERENCES daemons (id) ON DELETE SET NULL,
    ADD COLUMN edge_sni        TEXT[] NOT NULL DEFAULT '{}';

-- +goose Down

ALTER TABLE inbounds DROP COLUMN edge_daemon_id, DROP COLUMN edge_sni;
ALTER TABLE daemons DROP COLUMN edge_listen, DROP COLUMN edge_default;
