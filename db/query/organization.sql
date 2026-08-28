-- name: CreateOrganization :one
INSERT INTO organizations (
    name, slug, product_name, product_id
)
VALUES (
    $1, $2, $3, $4
)
RETURNING *;

-- name: GetOrgByID :one
SELECT * FROM organizations 
WHERE id = $1 LIMIT 1;

-- name: ListOrgs :many
SELECT o.id, o.name, o.slug, o.status, o.product_id, o.product_name,
       o.rc_number, o.sector, o.allocated_seats, o.created_at, o.updated_at,
       (SELECT COUNT(*) FROM members_accounts m WHERE m.org_id = o.id) AS member_count
FROM organizations o
WHERE ($1 = '' OR o.name ILIKE $2 OR o.slug ILIKE $2)
ORDER BY o.created_at DESC
LIMIT $3;

-- name: SetOrgStatus :exec
UPDATE organizations SET status = $2, updated_at = NOW() WHERE id = $1;

-- name: DashboardStats :one
SELECT
  (SELECT COUNT(*) FROM organizations) AS organizations,
  (SELECT COUNT(*) FROM organizations WHERE status = 'active') AS active_orgs,
  (SELECT COUNT(*) FROM users) AS users,
  (SELECT COUNT(*) FROM oauth_clients) AS apps,
  (SELECT COUNT(*) FROM oauth_clients WHERE is_active) AS active_apps;