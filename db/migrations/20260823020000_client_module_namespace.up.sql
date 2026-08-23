-- Links a product (OAuth client) to the purchasable-module catalog it sells,
-- so onboarding forms can offer exactly that product's features.
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS module_namespace VARCHAR(100) NOT NULL DEFAULT '';
