-- Track where a sidemenu item came from. 'product' rows are synced wholesale
-- from the product itself (terrasell's baked-in definition); 'manual' rows are
-- added by platform admins from the console and survive re-syncs.
ALTER TABLE sidemenu_items ADD COLUMN source VARCHAR(20) NOT NULL DEFAULT 'manual';
