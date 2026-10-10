-- name: ListNodes :many
SELECT * FROM nodes ORDER BY sort, id;

-- name: GetNode :one
SELECT * FROM nodes WHERE id = $1;

-- name: CreateNode :one
INSERT INTO nodes (name, address, country, tags, traffic_multiplier, traffic_limit, note, enabled, sort)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *;

-- name: UpdateNode :one
UPDATE nodes SET name = $2, address = $3, country = $4, tags = $5, traffic_multiplier = $6, traffic_limit = $7,
    note = $8, enabled = $9, sort = $10
WHERE id = $1 RETURNING *;

-- name: DeleteNode :execrows
DELETE FROM nodes WHERE id = $1;

-- name: AddNodeTraffic :exec
UPDATE nodes SET traffic_used = traffic_used + $2 WHERE id = $1;

-- name: ListDaemons :many
SELECT * FROM daemons ORDER BY node_id, id;

-- name: GetDaemon :one
SELECT * FROM daemons WHERE id = $1;

-- name: GetDaemonByToken :one
SELECT * FROM daemons WHERE token_hash = $1 AND enabled;

-- name: CreateDaemon :one
INSERT INTO daemons (node_id, kind, name, token_hash) VALUES ($1, $2, $3, $4) RETURNING *;

-- name: UpdateDaemon :one
UPDATE daemons SET name = $2, enabled = $3, log_level = $4, dns_servers = $5, dns_strategy = $6,
    final_outbound = $7, raw_patch = $8, edge_listen = $9, edge_default = $10
WHERE id = $1 RETURNING *;

-- name: RotateDaemonToken :exec
UPDATE daemons SET token_hash = $2 WHERE id = $1;

-- name: DeleteDaemon :execrows
DELETE FROM daemons WHERE id = $1;

-- name: SetDaemonHello :exec
UPDATE daemons SET core_version = $2, agent_version = $3, host_info = $4, last_seen = now() WHERE id = $1;

-- name: TouchDaemon :exec
UPDATE daemons SET last_seen = now() WHERE id = $1;

-- name: SetDaemonRevision :exec
UPDATE daemons SET desired_rev = $2, spec_hash = $3 WHERE id = $1;

-- name: SetDaemonApplied :exec
UPDATE daemons SET applied_rev = $2, last_error = $3 WHERE id = $1;
