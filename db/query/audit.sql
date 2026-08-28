-- name: InsertAuditEvent :one
INSERT INTO audit_events (
    user_id, org_id, event_type, details, ip_address, user_agent
)
VALUES (
    $1, $2, $3, NULLIF(CAST($4 AS text), '')::jsonb, $5, $6
)
RETURNING *;

-- name: ListAuditEvents :many
SELECT e.id, COALESCE(u.name, '') AS user_name, COALESCE(o.name, '') AS org_name, e.event_type, e.details, e.created_at
FROM audit_events e
LEFT JOIN users u ON u.id = e.user_id
LEFT JOIN organizations o ON o.id = e.org_id
WHERE ($1 = '' OR e.org_id::text = $1)
ORDER BY e.created_at DESC
LIMIT $2;