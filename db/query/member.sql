-- name: GetMemberByID :one
SELECT * FROM members_accounts 
WHERE id = $1 LIMIT 1;

-- name: GetMemberByEmail :one
SELECT * FROM members_accounts 
WHERE email = $1 LIMIT 1;

-- name: ListMembershipsForMember :many
SELECT o.id, o.slug, o.name, o.rc_number, o.sector, o.allocated_seats, m.role,
    COALESCE((
		SELECT array_agg(e.entitlement ORDER BY e.entitlement)
		FROM org_entitlements e WHERE e.org_id = o.id
	), '{}')
FROM members_accounts m
JOIN organizations o ON o.id = m.org_id
WHERE m.id = $1 AND o.status = 'active'
ORDER BY o.created_at;

-- name: ListMembersByOrg :many
SELECT id, org_id, role, email, is_active, name, given_name, family_name, picture, preferred_username, created_at
FROM members_accounts
WHERE org_id = $1
ORDER BY CASE role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, created_at;

-- name: GetMemberByOrgAndID :one
SELECT * FROM members_accounts
WHERE org_id = $1 AND id = $2 LIMIT 1;

-- name: GetMemberByOrgAndEmail :one
SELECT * FROM members_accounts
WHERE org_id = $1 AND email = $2 LIMIT 1;

-- name: CreateMember :one
INSERT INTO members_accounts (
    org_id, role, email, password_hash, name, given_name, family_name, picture, preferred_username, is_active
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
)
RETURNING *;

-- name: UpdateMemberRole :exec
UPDATE members_accounts SET role = $3, updated_at = NOW() WHERE org_id = $1 AND id = $2;

-- name: RemoveMember :exec
DELETE FROM members_accounts WHERE org_id = $1 AND id = $2;

-- name: CountMembersWithRole :one
SELECT COUNT(*) FROM members_accounts WHERE org_id = $1 AND role = $2;