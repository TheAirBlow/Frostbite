-- name: CreateUser :one
INSERT INTO users (username, uuid, password, sub_token, status, traffic_limit, reset_strategy, expire_at, on_hold_days,
    device_limit, ip_limit, tags, note, email, telegram_id, plan_id, owner_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) RETURNING *;

-- name: GetUser :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserBySubToken :one
SELECT * FROM users WHERE sub_token = $1;

-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = $1;

-- name: ListUsers :many
SELECT users.*, count(*) OVER() AS total FROM users
WHERE (sqlc.narg(status)::text IS NULL OR status = sqlc.narg(status))
  AND (sqlc.narg(search)::text IS NULL OR username ILIKE '%' || sqlc.narg(search) || '%'
       OR note ILIKE '%' || sqlc.narg(search) || '%' OR email ILIKE '%' || sqlc.narg(search) || '%')
  AND (sqlc.narg(owner)::bigint IS NULL OR owner_id = sqlc.narg(owner))
  AND (sqlc.narg(tag)::text IS NULL OR sqlc.narg(tag) = ANY(tags))
  AND (sqlc.narg(squad)::bigint IS NULL OR EXISTS (SELECT 1 FROM user_squads us WHERE us.user_id = users.id AND us.squad_id = sqlc.narg(squad)))
ORDER BY
  CASE WHEN sqlc.arg(sort)::text = 'used' THEN traffic_used END DESC NULLS LAST,
  CASE WHEN sqlc.arg(sort)::text = 'expire' THEN expire_at END ASC NULLS LAST,
  CASE WHEN sqlc.arg(sort)::text = 'online' THEN online_at END DESC NULLS LAST,
  CASE WHEN sqlc.arg(sort)::text = 'name' THEN username END ASC,
  id DESC
LIMIT sqlc.arg(max_rows)::int OFFSET sqlc.arg(skip)::int;

-- name: UpdateUser :one
UPDATE users SET username = $2, status = $3, traffic_limit = $4, reset_strategy = $5, expire_at = $6, on_hold_days = $7,
    device_limit = $8, ip_limit = $9, tags = $10, note = $11, email = $12, telegram_id = $13, plan_id = $14
WHERE id = $1 RETURNING *;

-- name: RotateUserSecrets :one
UPDATE users SET uuid = $2, password = $3 WHERE id = $1 RETURNING *;

-- name: RotateUserSubToken :one
UPDATE users SET sub_token = $2 WHERE id = $1 RETURNING *;

-- name: DeleteUsers :execrows
DELETE FROM users WHERE id = ANY(sqlc.arg(ids)::bigint[]);

-- name: SetUsersStatus :execrows
UPDATE users SET status = sqlc.arg(status)::text WHERE id = ANY(sqlc.arg(ids)::bigint[]);

-- name: ResetUsersTraffic :exec
UPDATE users SET traffic_used = 0, last_reset = now(), status = CASE WHEN status = 'limited' THEN 'active' ELSE status END
WHERE id = ANY(sqlc.arg(ids)::bigint[]);

-- name: ExtendUsers :exec
UPDATE users SET expire_at = COALESCE(GREATEST(expire_at, now()), now()) + make_interval(days => sqlc.arg(days)::int)
WHERE id = ANY(sqlc.arg(ids)::bigint[]);

-- name: AddUsersTraffic :exec
UPDATE users SET traffic_limit = GREATEST(traffic_limit + sqlc.arg(bytes)::bigint, 0)
WHERE id = ANY(sqlc.arg(ids)::bigint[]) AND traffic_limit > 0;

-- name: SetUsersOwner :exec
UPDATE users SET owner_id = sqlc.narg(owner_id)::bigint WHERE id = ANY(sqlc.arg(ids)::bigint[]);

-- name: AddUsersTags :exec
UPDATE users SET tags = (SELECT array_agg(DISTINCT t) FROM unnest(tags || sqlc.arg(new_tags)::text[]) t)
WHERE id = ANY(sqlc.arg(ids)::bigint[]);

-- name: RefreshUsersStatus :exec
UPDATE users SET status = 'active'
WHERE id = ANY(sqlc.arg(ids)::bigint[]) AND status IN ('expired', 'limited')
  AND (expire_at IS NULL OR expire_at > now()) AND (traffic_limit = 0 OR traffic_used < traffic_limit);

-- name: ListUserSquads :many
SELECT * FROM user_squads;

-- name: ListUserSquadIDs :many
SELECT squad_id FROM user_squads WHERE user_id = $1;

-- name: ClearUserSquads :exec
DELETE FROM user_squads WHERE user_id = ANY(sqlc.arg(ids)::bigint[]);

-- name: AddUserSquads :exec
INSERT INTO user_squads (user_id, squad_id)
SELECT u, s FROM unnest(sqlc.arg(ids)::bigint[]) u CROSS JOIN unnest(sqlc.arg(squad_ids)::bigint[]) s ON CONFLICT DO NOTHING;

-- name: TouchSub :exec
UPDATE users SET sub_last_at = now(), sub_last_ua = $2 WHERE id = $1;

-- name: BlockUser :exec
UPDATE users SET blocked_until = $2 WHERE id = $1;

-- name: ListServingUsers :many
SELECT * FROM users WHERE status IN ('active', 'on_hold') AND (blocked_until IS NULL OR blocked_until <= now());

-- name: AddUserUsage :one
UPDATE users SET traffic_used = traffic_used + $2, traffic_lifetime = traffic_lifetime + $2, online_at = now()
WHERE id = $1 RETURNING *;

-- name: ExpireUsers :many
UPDATE users SET status = 'expired'
WHERE status IN ('active', 'on_hold') AND expire_at IS NOT NULL AND expire_at <= now() RETURNING id;

-- name: LimitUsers :many
UPDATE users SET status = 'limited'
WHERE status IN ('active', 'on_hold') AND traffic_limit > 0 AND traffic_used >= traffic_limit RETURNING id;

-- name: ResetDueUsers :many
UPDATE users SET traffic_used = 0, last_reset = now(), status = CASE WHEN status = 'limited' THEN 'active' ELSE status END
WHERE reset_strategy <> 'none' AND last_reset + (CASE reset_strategy
        WHEN 'day' THEN interval '1 day' WHEN 'week' THEN interval '7 days'
        WHEN 'month' THEN interval '1 month' ELSE interval '1 year' END) <= now()
RETURNING id;

-- name: ActivateOnHold :many
UPDATE users SET status = 'active',
    expire_at = CASE WHEN on_hold_days > 0 THEN now() + make_interval(days => on_hold_days) ELSE expire_at END
WHERE status = 'on_hold' AND traffic_used > 0 RETURNING id;

-- name: ClearExpiredBlocks :many
UPDATE users SET blocked_until = NULL WHERE blocked_until IS NOT NULL AND blocked_until <= now() RETURNING id;

-- name: CountUsersByStatus :many
SELECT status, count(*) AS count FROM users GROUP BY status;

-- name: CountOnlineUsers :one
SELECT count(*) FROM users WHERE online_at > now() - interval '3 minutes';

-- name: ListDevices :many
SELECT * FROM user_devices WHERE user_id = $1 ORDER BY last_seen DESC;

-- name: CountDevices :one
SELECT count(*) FROM user_devices WHERE user_id = $1;

-- name: GetDevice :one
SELECT * FROM user_devices WHERE user_id = $1 AND hwid = $2;

-- name: UpsertDevice :exec
INSERT INTO user_devices (user_id, hwid, platform, model, os_version, user_agent)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (user_id, hwid) DO UPDATE SET last_seen = now(), user_agent = EXCLUDED.user_agent;

-- name: DeleteDevice :execrows
DELETE FROM user_devices WHERE id = $1 AND user_id = $2;

-- name: AddTraffic :exec
INSERT INTO traffic_hourly (user_id, node_id, hour, up, down) VALUES ($1, $2, date_trunc('hour', now()), $3, $4)
ON CONFLICT (user_id, node_id, hour) DO UPDATE SET up = traffic_hourly.up + EXCLUDED.up, down = traffic_hourly.down + EXCLUDED.down;

-- name: TrafficSeries :many
SELECT hour, sum(up)::bigint AS up, sum(down)::bigint AS down FROM traffic_hourly
WHERE hour >= sqlc.arg(since)::timestamptz AND (sqlc.narg(user_id)::bigint IS NULL OR user_id = sqlc.narg(user_id))
  AND (sqlc.narg(node_id)::bigint IS NULL OR node_id = sqlc.narg(node_id))
GROUP BY hour ORDER BY hour;

-- name: TrafficByNode :many
SELECT node_id, sum(up)::bigint AS up, sum(down)::bigint AS down FROM traffic_hourly
WHERE hour >= sqlc.arg(since)::timestamptz AND (sqlc.narg(user_id)::bigint IS NULL OR user_id = sqlc.narg(user_id)) GROUP BY node_id;

-- name: TopUsers :many
SELECT u.id, u.username, sum(t.up + t.down)::bigint AS total FROM traffic_hourly t JOIN users u ON u.id = t.user_id
WHERE t.hour >= $1 GROUP BY u.id, u.username ORDER BY total DESC LIMIT $2;

-- name: PruneTraffic :exec
DELETE FROM traffic_hourly WHERE hour < $1;

-- name: ListUserSquadsByUsers :many
SELECT * FROM user_squads WHERE user_id = ANY(sqlc.arg(ids)::bigint[]);

-- name: OwnerTotals :one
SELECT count(*)::bigint AS users, COALESCE(sum(traffic_limit), 0)::bigint AS allocated, COALESCE(sum(traffic_used), 0)::bigint AS used
FROM users WHERE owner_id = $1;

-- name: SetUserUsed :exec
UPDATE users SET traffic_used = $2, traffic_lifetime = GREATEST(traffic_lifetime, $2) WHERE id = $1;
