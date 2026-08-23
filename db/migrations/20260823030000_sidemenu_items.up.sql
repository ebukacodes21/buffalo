-- Per-product sidemenu definitions, managed from the Arkad console. Products
-- pull their menu and show an item only when its required entitlement is in
-- the signed-in business's paid set (empty entitlement = always visible).
CREATE TABLE sidemenu_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id VARCHAR(100) NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    label VARCHAR(255) NOT NULL,
    icon VARCHAR(100) NOT NULL DEFAULT '',
    href VARCHAR(500) NOT NULL,
    section VARCHAR(100) NOT NULL DEFAULT '',
    required_entitlement VARCHAR(100) NOT NULL DEFAULT '',
    sort_order INT NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sidemenu_items_client ON sidemenu_items(client_id, is_active, sort_order);
