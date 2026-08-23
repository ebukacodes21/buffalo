-- Declarative catalog of purchasable product modules. The console reads it
-- to render entitlement pickers; buffalo stays the single source of truth
-- for both the catalog and the per-org org_entitlements that reference it.
-- Entitlement keys remain "<namespace>:<module_key>".
CREATE TABLE product_modules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    namespace VARCHAR(100) NOT NULL,
    module_key VARCHAR(100) NOT NULL,
    label VARCHAR(255) NOT NULL,
    hint VARCHAR(500) NOT NULL DEFAULT '',
    sort_order INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(namespace, module_key)
);

CREATE INDEX idx_product_modules_namespace ON product_modules(namespace);

INSERT INTO product_modules (namespace, module_key, label, hint, sort_order) VALUES
    ('terrasell', 'healthcare',   'Life-sciences SFA',        'e-detailing, samples, RCPA', 10),
    ('terrasell', 'trade',        'FMCG trade management',    'secondary sales, outlet audits, listing signals', 20),
    ('terrasell', 'logistics',    'Logistics & deliveries',   'delivery runs, driver routes, delivery map', 30),
    ('terrasell', 'warehousing',  'Warehousing',              'warehouse operations', 40),
    ('terrasell', 'ai_insights',  'AI insights',              'forecasts, conversion & RTM insights', 50);
