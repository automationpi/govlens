-- GovLens fresh-init: drops ONLY GovLens-owned tables (CASCADE for foreign keys),
-- so a bring-your-own Postgres that also hosts other apps keeps their tables intact.
-- Runs only when database.init = "fresh"; the schema is recreated immediately after.
DROP TABLE IF EXISTS principal_activity CASCADE;
DROP TABLE IF EXISTS admin_audit CASCADE;
DROP TABLE IF EXISTS catalog_override CASCADE;
DROP TABLE IF EXISTS grant_tier_policy CASCADE;
DROP TABLE IF EXISTS role_catalog CASCADE;
DROP TABLE IF EXISTS grant_sp CASCADE;
DROP TABLE IF EXISTS module_settings CASCADE;
DROP TABLE IF EXISTS assignments CASCADE;
DROP TABLE IF EXISTS findings CASCADE;
DROP TABLE IF EXISTS metrics CASCADE;
DROP TABLE IF EXISTS type_policies CASCADE;
DROP TABLE IF EXISTS protected_roles CASCADE;
DROP TABLE IF EXISTS user_scope_roles CASCADE;
DROP TABLE IF EXISTS resource_groups CASCADE;
DROP TABLE IF EXISTS subscriptions CASCADE;
DROP TABLE IF EXISTS app_users CASCADE;
DROP TABLE IF EXISTS access_requests CASCADE;
DROP TABLE IF EXISTS revoke_requests CASCADE; -- legacy name (pre-rename to access_requests)
DROP TABLE IF EXISTS runs CASCADE;
