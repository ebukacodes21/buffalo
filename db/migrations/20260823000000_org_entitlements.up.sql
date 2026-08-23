-- Per-business paid entitlements. The Arkad console manages which product
-- modules an organization has paid for; products (TerraSell, TerraBooks, ...)
-- read them via the organizations claim on tokens/userinfo and gate their UI.
CREATE TABLE org_entitlements (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    entitlement VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, entitlement)
);

CREATE INDEX idx_org_entitlements_org ON org_entitlements(org_id);
