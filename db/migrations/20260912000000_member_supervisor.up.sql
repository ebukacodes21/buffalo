-- Every member may report to a supervisor. The supervisor is another member
-- of the same organization, referenced by UUID. The workspace admin uses the
-- null UUID (00000000-0000-0000-0000-000000000000) to indicate no supervisor.
ALTER TABLE members_accounts ADD COLUMN supervisor_id UUID;

CREATE INDEX idx_members_accounts_supervisor ON members_accounts(supervisor_id);
