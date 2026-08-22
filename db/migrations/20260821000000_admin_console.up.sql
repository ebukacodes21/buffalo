-- Admin Console / Backoffice schema

ALTER TABLE users ADD COLUMN is_platform_admin BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE organizations ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'active';

CREATE TABLE admin_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token VARCHAR(128) UNIQUE NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_admin_sessions_token ON admin_sessions(token);
CREATE INDEX idx_admin_sessions_user ON admin_sessions(user_id);
CREATE INDEX idx_admin_sessions_expires ON admin_sessions(expires_at);
