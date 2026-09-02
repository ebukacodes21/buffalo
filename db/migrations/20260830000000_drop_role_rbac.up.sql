-- Role RBAC moved into the product (terrasell owns the role matrix; identity
-- stays here). Drop the platform-owned role tables now unused by the API.
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS permissions;