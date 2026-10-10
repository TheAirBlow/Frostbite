-- name: ListSquads :many
SELECT * FROM squads ORDER BY id;

-- name: GetSquad :one
SELECT * FROM squads WHERE id = $1;

-- name: CreateSquad :one
INSERT INTO squads (name, note) VALUES ($1, $2) RETURNING *;

-- name: UpdateSquad :one
UPDATE squads SET name = $2, note = $3 WHERE id = $1 RETURNING *;

-- name: DeleteSquad :execrows
DELETE FROM squads WHERE id = $1;

-- name: ListSquadInbounds :many
SELECT * FROM squad_inbounds;

-- name: ClearSquadInbounds :exec
DELETE FROM squad_inbounds WHERE squad_id = $1;

-- name: AddSquadInbounds :exec
INSERT INTO squad_inbounds (squad_id, inbound_id)
SELECT sqlc.arg(squad_id)::bigint, unnest(sqlc.arg(inbound_ids)::bigint[]) ON CONFLICT DO NOTHING;

-- name: ListPlans :many
SELECT * FROM plans ORDER BY id;

-- name: GetPlan :one
SELECT * FROM plans WHERE id = $1;

-- name: CreatePlan :one
INSERT INTO plans (name, traffic_limit, duration_days, reset_strategy, start_on_first_use, device_limit, ip_limit, squad_ids, note)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *;

-- name: UpdatePlan :one
UPDATE plans SET name = $2, traffic_limit = $3, duration_days = $4, reset_strategy = $5, start_on_first_use = $6,
    device_limit = $7, ip_limit = $8, squad_ids = $9, note = $10
WHERE id = $1 RETURNING *;

-- name: DeletePlan :execrows
DELETE FROM plans WHERE id = $1;

-- name: ListSubTemplates :many
SELECT * FROM sub_templates ORDER BY id;

-- name: GetSubTemplate :one
SELECT * FROM sub_templates WHERE id = $1;

-- name: CreateSubTemplate :one
INSERT INTO sub_templates (name, format, patch) VALUES ($1, $2, $3) RETURNING *;

-- name: UpdateSubTemplate :one
UPDATE sub_templates SET name = $2, format = $3, patch = $4 WHERE id = $1 RETURNING *;

-- name: DeleteSubTemplate :execrows
DELETE FROM sub_templates WHERE id = $1;

-- name: ListSubRules :many
SELECT * FROM sub_rules ORDER BY sort, id;

-- name: CreateSubRule :one
INSERT INTO sub_rules (name, ua_regex, format, template_id, enabled, sort) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *;

-- name: UpdateSubRule :one
UPDATE sub_rules SET name = $2, ua_regex = $3, format = $4, template_id = $5, enabled = $6, sort = $7 WHERE id = $1 RETURNING *;

-- name: DeleteSubRule :execrows
DELETE FROM sub_rules WHERE id = $1;
