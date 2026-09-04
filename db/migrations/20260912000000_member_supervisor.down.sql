DROP INDEX IF EXISTS idx_members_accounts_supervisor;
ALTER TABLE members_accounts DROP COLUMN IF EXISTS supervisor_id;
