-- name: TryNotify :execrows
INSERT INTO notification_log (kind, key) VALUES ($1, $2) ON CONFLICT DO NOTHING;

-- name: PruneNotifications :exec
DELETE FROM notification_log WHERE sent_at < $1;

-- name: ListNotifyCandidates :many
SELECT * FROM users
WHERE status IN ('active', 'on_hold')
  AND ((expire_at IS NOT NULL AND expire_at < now() + interval '15 days')
       OR (traffic_limit > 0 AND traffic_used * 2 >= traffic_limit));

-- name: GetUserByTelegram :one
SELECT * FROM users WHERE telegram_id = $1 ORDER BY id LIMIT 1;

-- name: SetUserTelegram :exec
UPDATE users SET telegram_id = $2 WHERE id = $1;
