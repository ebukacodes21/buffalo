DROP TABLE IF EXISTS admin_sessions;
ALTER TABLE organizations DROP COLUMN IF EXISTS status;
ALTER TABLE users DROP COLUMN IF EXISTS is_platform_admin;
