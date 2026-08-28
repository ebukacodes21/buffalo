-- name: CreateAdmin :one
INSERT INTO users (
    email,
    password_hash,
    name
)
VALUES (
    $1, $2, $3
)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users 
WHERE id = $1 LIMIT 1;

-- name: GetUserByEmail :one
SELECT * FROM users 
WHERE email = $1 LIMIT 1;

-- name: ListUsers :many
SELECT id, email, name, email_verified, is_active, is_platform_admin, created_at
FROM users
WHERE ($1 = '' OR email ILIKE $2 OR name ILIKE $2)
ORDER BY created_at DESC
LIMIT $3;

-- name: SetUserActive :exec
UPDATE users SET is_active = $2, updated_at = NOW() WHERE id = $1;