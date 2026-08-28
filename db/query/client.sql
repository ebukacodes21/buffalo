-- name: CreateOAuthClient :one
INSERT INTO oauth_clients (
    client_id, client_secret, name, redirect_uris, base_url
)
VALUES (
    $1, $2, $3, $4, $5
)
RETURNING *;

-- name: GetActiveClientByClientID :one
SELECT * FROM oauth_clients 
WHERE client_id = $1 LIMIT 1;

-- name: GetClientByID :one
SELECT * FROM oauth_clients 
WHERE id = $1 LIMIT 1;

-- name: ListOAuthClients :many
SELECT * FROM oauth_clients
WHERE ($1 = '' OR name ILIKE $2 OR client_id ILIKE $2)
ORDER BY created_at DESC
LIMIT $3;

-- name: UpdateOAuthClient :exec
UPDATE oauth_clients
SET name = $2, redirect_uris = $3, is_active = $4, base_url = $5, updated_at = NOW()
WHERE id = $1;

-- name: RotateOAuthClientSecret :exec
UPDATE oauth_clients SET client_secret = $2, updated_at = NOW() WHERE id = $1;