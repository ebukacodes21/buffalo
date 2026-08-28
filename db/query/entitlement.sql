-- name: ListEntitlements :many
SELECT entitlement
FROM org_entitlements
WHERE org_id = $1
ORDER BY entitlement;

-- name: DeleteEntitlements :exec
DELETE FROM org_entitlements WHERE org_id = $1;

-- name: UpsertEntitlement :exec
INSERT INTO org_entitlements (org_id, entitlement) VALUES ($1, $2)
ON CONFLICT (org_id, entitlement) DO NOTHING;
