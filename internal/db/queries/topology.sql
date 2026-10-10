-- name: ListInbounds :many
SELECT * FROM inbounds ORDER BY daemon_id, sort, id;

-- name: ListInboundsByDaemon :many
SELECT * FROM inbounds WHERE daemon_id = $1 ORDER BY sort, id;

-- name: GetInbound :one
SELECT * FROM inbounds WHERE id = $1;

-- name: CreateInbound :one
INSERT INTO inbounds (daemon_id, tag, remark, protocol, listen, port, transport, security, options, sniffing, forward, raw_patch, enabled, system, sort, edge_daemon_id, edge_sni)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) RETURNING *;

-- name: UpdateInbound :one
UPDATE inbounds SET tag = $2, remark = $3, protocol = $4, listen = $5, port = $6, transport = $7, security = $8,
    options = $9, sniffing = $10, forward = $11, raw_patch = $12, enabled = $13, sort = $14, edge_daemon_id = $15, edge_sni = $16
WHERE id = $1 RETURNING *;

-- name: DeleteInbound :execrows
DELETE FROM inbounds WHERE id = $1;

-- name: ListHosts :many
SELECT * FROM hosts ORDER BY inbound_id, sort, id;

-- name: GetHost :one
SELECT * FROM hosts WHERE id = $1;

-- name: CreateHost :one
INSERT INTO hosts (inbound_id, bridge_inbound_id, remark, address, port, sni, host, path, alpn, fingerprint, insecure, mux, fragment, enabled, sort)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) RETURNING *;

-- name: UpdateHost :one
UPDATE hosts SET remark = $2, address = $3, port = $4, sni = $5, host = $6, path = $7, alpn = $8, fingerprint = $9,
    insecure = $10, mux = $11, fragment = $12, enabled = $13, sort = $14
WHERE id = $1 RETURNING *;

-- name: DeleteHost :execrows
DELETE FROM hosts WHERE id = $1;

-- name: ListOutbounds :many
SELECT * FROM outbounds ORDER BY daemon_id, sort, id;

-- name: GetOutbound :one
SELECT * FROM outbounds WHERE id = $1;

-- name: CreateOutbound :one
INSERT INTO outbounds (daemon_id, tag, kind, upstream, target_inbound_id, interface, strategy, sort)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *;

-- name: UpdateOutbound :one
UPDATE outbounds SET tag = $2, kind = $3, upstream = $4, target_inbound_id = $5, interface = $6, strategy = $7, sort = $8
WHERE id = $1 RETURNING *;

-- name: DeleteOutbound :execrows
DELETE FROM outbounds WHERE id = $1;

-- name: ListRules :many
SELECT * FROM rules ORDER BY sort, id;

-- name: GetRule :one
SELECT * FROM rules WHERE id = $1;

-- name: CreateRule :one
INSERT INTO rules (daemon_id, name, match, outbound, enabled, sort) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *;

-- name: UpdateRule :one
UPDATE rules SET daemon_id = $2, name = $3, match = $4, outbound = $5, enabled = $6, sort = $7 WHERE id = $1 RETURNING *;

-- name: DeleteRule :execrows
DELETE FROM rules WHERE id = $1;
