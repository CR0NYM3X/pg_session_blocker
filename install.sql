-- ============================================================================
-- pg-login-guard: PostgreSQL Login Auditing & Application Control
-- Version: 2.0.0
-- Requires: PostgreSQL 12+ | Extension: login_hook
-- License: MIT
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. SCHEMA: Isolated namespace to avoid polluting public schema
-- ---------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS sec_dba AUTHORIZATION postgres;

COMMENT ON SCHEMA sec_dba IS 'Security DBA schema — login auditing and application control functions';


-- ---------------------------------------------------------------------------
-- 2. CONFIGURATION TABLE: Blocked applications (replaces hardcoded patterns)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec_dba.blocked_applications (
    id              SERIAL PRIMARY KEY,
    app_pattern     TEXT        NOT NULL,           -- ILIKE pattern, e.g. '%DBeaver%'
    description     TEXT,                           -- Human-readable reason
    is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
    log_on_success BOOLEAN NOT NULL DEFAULT FALSE,
    log_on_failure BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      TEXT        NOT NULL DEFAULT current_user
);


 

COMMENT ON TABLE sec_dba.blocked_applications IS
    'Applications blocked from connecting. Patterns are matched with ILIKE against application_name.';

-- Default blocked applications
INSERT INTO sec_dba.blocked_applications (app_pattern, description)
VALUES
    ('%DBeaver%',   'DBeaver IDE — not authorized for production'),
    ('%Navicat%',   'Navicat — not authorized for production'),
    ('%psql%',   'Psql — not authorized for production')
ON CONFLICT DO NOTHING;


-- ---------------------------------------------------------------------------
-- 3. CONFIGURATION TABLE: Exempt users (service accounts, DBAs, etc.)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec_dba.blocked_users (
    id              SERIAL PRIMARY KEY,
    username_pattern TEXT       NOT NULL,            -- Regex pattern, e.g. '^(dba_|svc_)'
    description     TEXT,
    is_active       BOOLEAN    NOT NULL DEFAULT TRUE,
    block BOOLEAN    NOT NULL DEFAULT FALSE, -- Default: alerts only
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      TEXT        NOT NULL DEFAULT current_user
);

COMMENT ON TABLE sec_dba.exempt_users IS
    'Users exempt from application checks. Patterns matched with ~ (regex) against session_user.';

-- Default exempt pattern: users whose name starts with a digit (legacy behavior)
INSERT INTO sec_dba.exempt_users (username_pattern, description)
VALUES
    ('^[0-9]', 'Numeric-prefixed service accounts')
ON CONFLICT DO NOTHING;


-- ---------------------------------------------------------------------------
-- 4. AUDIT LOG TABLE: Replaces CSV files — queryable, indexable, rotatable
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec_dba.login_audit_log (
    id              BIGSERIAL   PRIMARY KEY,
    event_id        UUID        NOT NULL DEFAULT gen_random_uuid(),
    event_type      TEXT        NOT NULL CHECK (event_type IN ('ALLOWED', 'BLOCKED')),
    server_ip       INET,
    server_port     INT,
    database_name   TEXT        NOT NULL,
    session_user_   TEXT        NOT NULL,       -- trailing underscore avoids reserved-word clash
    client_ip       INET,
    application_name TEXT,
    event_time      TIMESTAMPTZ NOT NULL DEFAULT now(),
    message         TEXT
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_login_audit_event_time
    ON sec_dba.login_audit_log (event_time DESC);

CREATE INDEX IF NOT EXISTS idx_login_audit_user
    ON sec_dba.login_audit_log (session_user_);

CREATE INDEX IF NOT EXISTS idx_login_audit_type
    ON sec_dba.login_audit_log (event_type)
    WHERE event_type = 'BLOCKED';

COMMENT ON TABLE sec_dba.login_audit_log IS
    'Audit trail for all login events processed by sec_dba.login(). Partitioning by event_time is recommended for high-traffic clusters.';


-- ---------------------------------------------------------------------------
-- 5. MAIN FUNCTION: login()
-- ---------------------------------------------------------------------------



-- ---------------------------------------------------------------------------
-- 6. OWNERSHIP & PERMISSIONS
-- ---------------------------------------------------------------------------

-- Owner with minimal privileges (no superuser)
ALTER FUNCTION sec_dba.login() OWNER TO postgres;

-- All users must execute this function (login_hook calls it per-session)
GRANT USAGE    ON SCHEMA sec_dba                TO PUBLIC;
GRANT EXECUTE  ON FUNCTION sec_dba.login()  TO PUBLIC;

-- Only DBAs should modify configuration tables
REVOKE ALL ON sec_dba.blocked_applications FROM PUBLIC;
REVOKE ALL ON sec_dba.exempt_users          FROM PUBLIC;
REVOKE ALL ON sec_dba.login_audit_log       FROM PUBLIC;

-- Grant read-only on audit log to PUBLIC so users can see their own events
-- (row-level security can be added for tighter control)
GRANT SELECT ON sec_dba.login_audit_log TO PUBLIC;


-- ---------------------------------------------------------------------------
-- 7. CONFIGURE login_hook TO CALL THIS FUNCTION
-- ---------------------------------------------------------------------------
-- Add to postgresql.conf:
--   shared_preload_libraries = 'login_hook'
--   login_hook.login = 'sec_dba.check_app'
-- Then: SELECT pg_reload_conf();  (or restart PostgreSQL)

DO $$
BEGIN
    RAISE NOTICE E'\n============================================================';
    RAISE NOTICE '  pg-login-guard installed successfully!';
    RAISE NOTICE '  ';
    RAISE NOTICE '  Next steps:';
    RAISE NOTICE '  1. Add to postgresql.conf:';
    RAISE NOTICE '     shared_preload_libraries = ''login_hook''';
    RAISE NOTICE '     login_hook.login = ''sec_dba.check_app''';
    RAISE NOTICE '  2. Restart PostgreSQL';
    RAISE NOTICE '  3. Customize blocked apps:';
    RAISE NOTICE '     INSERT INTO sec_dba.blocked_applications (app_pattern, description)';
    RAISE NOTICE '     VALUES (''%%pgAdmin%%'', ''pgAdmin blocked'');';
    RAISE NOTICE E'============================================================\n';
END;
$$;
