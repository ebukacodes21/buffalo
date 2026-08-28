-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (token, client_id, subject_type, subject_id, scope, expires_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetRefreshToken :one
SELECT client_id, subject_type, subject_id, scope
FROM refresh_tokens
WHERE token = $1 AND revoked = FALSE AND expires_at > NOW();

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens SET revoked = TRUE WHERE token = $1;
