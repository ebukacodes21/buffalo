-- name: CreatePasswordReset :exec
INSERT INTO password_resets (subject_id, token, expires_at)
VALUES ($1, $2, $3);

-- name: GetPasswordReset :one
SELECT subject_id
FROM password_resets
WHERE token = $1 AND used = FALSE AND expires_at > NOW();

-- name: MarkPasswordResetUsed :exec
UPDATE password_resets SET used = TRUE WHERE token = $1;

-- name: UpdateMemberPasswordHash :exec
UPDATE members_accounts SET password_hash = $2, updated_at = NOW() WHERE id = $1;
