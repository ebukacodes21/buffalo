-- Where each product serves its platform-facing API. The stateless console
-- reads this to reach the product's GET endpoints (e.g. /api/product/*).
ALTER TABLE oauth_clients ADD COLUMN base_url VARCHAR(500) NOT NULL DEFAULT '';
