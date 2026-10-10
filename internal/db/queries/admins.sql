-- name: CreateAdmin :one
INSERT INTO admins (username, password_hash, role, user_quota, traffic_quota, note)
VALUES ($1, $2, $3, $4, $5, $6) RETURNING *;

-- name: GetAdminByUsername :one
SELECT * FROM admins WHERE username = $1;

-- name: GetAdminByID :one
SELECT * FROM admins WHERE id = $1;

-- name: ListAdmins :many
SELECT * FROM admins ORDER BY id;

-- name: CountAdmins :one
SELECT count(*) FROM admins;

-- name: UpdateAdmin :one
UPDATE admins SET role = $2, enabled = $3, user_quota = $4, traffic_quota = $5, note = $6
WHERE id = $1 RETURNING *;

-- name: UpdateAdminPassword :exec
UPDATE admins SET password_hash = $2 WHERE id = $1;

-- name: DeleteAdmin :execrows
DELETE FROM admins WHERE id = $1;

-- name: CreateSession :exec
INSERT INTO sessions (admin_id, token_hash, user_agent, ip, expires_at) VALUES ($1, $2, $3, $4, $5);

-- name: GetSessionAdmin :one
SELECT a.* FROM sessions s JOIN admins a ON a.id = s.admin_id
WHERE s.token_hash = $1 AND s.expires_at > now() AND a.enabled;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE token_hash = $1;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at <= now();

-- name: CreateAPIToken :one
INSERT INTO api_tokens (admin_id, name, token_hash) VALUES ($1, $2, $3) RETURNING *;

-- name: GetAPITokenAdmin :one
SELECT a.* FROM api_tokens t JOIN admins a ON a.id = t.admin_id WHERE t.token_hash = $1 AND a.enabled;

-- name: TouchAPIToken :exec
UPDATE api_tokens SET last_used_at = now() WHERE token_hash = $1;

-- name: ListAPITokens :many
SELECT * FROM api_tokens WHERE admin_id = $1 ORDER BY id;

-- name: DeleteAPIToken :execrows
DELETE FROM api_tokens WHERE id = $1 AND admin_id = $2;

-- name: InsertAudit :exec
INSERT INTO audit_log (admin_id, admin_name, action, target, detail) VALUES ($1, $2, $3, $4, $5);

-- name: ListAudit :many
SELECT * FROM audit_log ORDER BY id DESC LIMIT $1 OFFSET $2;

-- name: GetSetting :one
SELECT value FROM settings WHERE key = $1;

-- name: SetSetting :exec
INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;

-- name: ListSettings :many
SELECT * FROM settings;
