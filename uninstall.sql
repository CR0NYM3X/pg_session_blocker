-- ============================================================================
-- pg-login-guard: UNINSTALL
-- Removes all objects created by install.sql
-- ============================================================================
 
-- Remove login_hook configuration first (requires postgresql.conf edit + reload)
-- login_hook.login = ''
 
DROP FUNCTION IF EXISTS sec_dba.check_app() CASCADE;
DROP TABLE   IF EXISTS sec_dba.login_audit_log      CASCADE;
DROP TABLE   IF EXISTS sec_dba.blocked_applications  CASCADE;
DROP TABLE   IF EXISTS sec_dba.exempt_users           CASCADE;
DROP SCHEMA  IF EXISTS sec_dba CASCADE;
 
DO $$
BEGIN
    RAISE NOTICE 'pg-login-guard uninstalled. Remember to remove login_hook settings from postgresql.conf and reload.';
END;
$$;
 
