-- audit_events.user_id originally referenced users(id), but the product-scoped
-- member API writes a members_accounts.id there (when a member invites/re-roles
-- another member). The FK blocked every such insert. Audit events are historical
-- records; dropping the constraint lets both user and member actor IDs be stored.
ALTER TABLE audit_events
    DROP CONSTRAINT IF EXISTS audit_events_user_id_fkey;
