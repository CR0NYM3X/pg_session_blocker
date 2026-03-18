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
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      TEXT        NOT NULL DEFAULT current_user
);

COMMENT ON TABLE sec_dba.blocked_applications IS
    'Applications blocked from connecting. Patterns are matched with ILIKE against application_name.';

-- Default blocked applications
INSERT INTO sec_dba.blocked_applications (app_pattern, description)
VALUES
    ('%DBeaver%',   'DBeaver IDE — not authorized for production'),
    ('%Navicat%',   'Navicat — not authorized for production')
ON CONFLICT DO NOTHING;


-- ---------------------------------------------------------------------------
-- 3. CONFIGURATION TABLE: Exempt users (service accounts, DBAs, etc.)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec_dba.exempt_users (
    id              SERIAL PRIMARY KEY,
    username_pattern TEXT       NOT NULL,            -- Regex pattern, e.g. '^(dba_|svc_)'
    description     TEXT,
    is_active       BOOLEAN    NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      TEXT        NOT NULL DEFAULT current_user
);

COMMENT ON TABLE sec_dba.exempt_users IS
    'Users exempt from application checks. Patterns matched with ~ (regex) against session_user.';

-- Default exempt pattern: users whose name starts with a digit (legacy behavior)
INSERT INTO sec_dba.exempt_users (username_pattern, description)
VALUES
    ('^[0-9]', 'Numeric-prefixed service accounts are exempt')
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
    'Audit trail for all login events processed by sec_dba.check_app(). Partitioning by event_time is recommended for high-traffic clusters.';


-- ---------------------------------------------------------------------------
-- 5. MAIN FUNCTION: check_app()
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION sec_dba.check_app()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = sec_dba, pg_catalog
SET client_min_messages = notice
SET client_encoding   = 'UTF-8'
AS $$
DECLARE
    v_app_name      TEXT    := current_setting('application_name', true);
    v_session_user  TEXT    := session_user;
    v_database      TEXT    := current_database();
    v_server_ip     INET;
    v_client_ip     INET;
    v_server_port   INT;
    v_is_blocked    BOOLEAN := FALSE;
    v_is_exempt     BOOLEAN := FALSE;
    v_matched_app   TEXT;
BEGIN
    -- -----------------------------------------------------------------------
    -- Guard: Prevent manual invocation outside login_hook context.
    -- During login_hook execution the backend PID is not yet visible
    -- in pg_stat_activity, so if it IS visible, this is a manual call.
    -- -----------------------------------------------------------------------
    IF EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = pg_backend_pid()) THEN
        RAISE EXCEPTION 'sec_dba.check_app() is designed for login_hook only and cannot be invoked manually.';
    END IF;

    -- -----------------------------------------------------------------------
    -- Gather connection metadata (safe defaults for local/unix sockets)
    -- -----------------------------------------------------------------------
    v_server_ip   := inet_server_addr();        -- NULL on unix socket
    v_client_ip   := inet_client_addr();        -- NULL on unix socket
    v_server_port := inet_server_port();

    -- -----------------------------------------------------------------------
    -- Check if the user is exempt from application restrictions
    -- -----------------------------------------------------------------------
    SELECT TRUE INTO v_is_exempt
    FROM sec_dba.exempt_users
    WHERE is_active
      AND v_session_user ~ username_pattern
    LIMIT 1;

    v_is_exempt := COALESCE(v_is_exempt, FALSE);

    -- -----------------------------------------------------------------------
    -- Check if the application is in the blocked list
    -- -----------------------------------------------------------------------
    IF NOT v_is_exempt THEN
        SELECT TRUE, ba.app_pattern
          INTO v_is_blocked, v_matched_app
        FROM sec_dba.blocked_applications ba
        WHERE ba.is_active
          AND v_app_name ILIKE ba.app_pattern
        LIMIT 1;

        v_is_blocked := COALESCE(v_is_blocked, FALSE);
    END IF;

    -- -----------------------------------------------------------------------
    -- Audit & enforce
    -- -----------------------------------------------------------------------
    IF v_is_blocked THEN
        -- Log blocked attempt
        INSERT INTO sec_dba.login_audit_log
            (event_type, server_ip, server_port, database_name,
             session_user_, client_ip, application_name, message)
        VALUES
            ('BLOCKED', v_server_ip, v_server_port, v_database,
             v_session_user, v_client_ip, v_app_name,
             format('Blocked by pattern: %s', v_matched_app));

        -- Reject the connection with a clear, actionable message
        RAISE EXCEPTION E'\n\n'
            '╔══════════════════════════════════════════════════════════════╗\n'
            '║              UNAUTHORIZED APPLICATION DETECTED             ║\n'
            '╠══════════════════════════════════════════════════════════════╣\n'
            '║  User:        %-45s  ║\n'
            '║  Database:    %-45s  ║\n'
            '║  Application: %-45s  ║\n'
            '╠══════════════════════════════════════════════════════════════╣\n'
            '║  This application is not authorized per security policy.   ║\n'
            '║  Contact the DBA Security team if you believe this is an   ║\n'
            '║  error.                                                    ║\n'
            '╚══════════════════════════════════════════════════════════════╝\n',
            v_session_user, v_database, v_app_name;
    ELSE
        -- Log successful connection
        INSERT INTO sec_dba.login_audit_log
            (event_type, server_ip, server_port, database_name,
             session_user_, client_ip, application_name, message)
        VALUES
            ('ALLOWED', v_server_ip, v_server_port, v_database,
             v_session_user, v_client_ip, v_app_name,
             'Connection authorized');
    END IF;

EXCEPTION
    WHEN OTHERS THEN
        -- Re-raise blocking exceptions (our own RAISE EXCEPTION above)
        IF SQLERRM ILIKE '%UNAUTHORIZED APPLICATION%' OR
           SQLERRM ILIKE '%login_hook only%' THEN
            RAISE;
        END IF;
        -- Swallow unexpected errors so a bug in auditing never locks users out.
        -- Log to PostgreSQL server log for ops visibility.
        RAISE WARNING 'sec_dba.check_app() unexpected error (connection allowed): % — %',
                       SQLSTATE, SQLERRM;
END;
$$;


-- ---------------------------------------------------------------------------
-- 6. OWNERSHIP & PERMISSIONS
-- ---------------------------------------------------------------------------

-- Owner with minimal privileges (no superuser)
ALTER FUNCTION sec_dba.check_app() OWNER TO postgres;

-- All users must execute this function (login_hook calls it per-session)
GRANT USAGE    ON SCHEMA sec_dba                TO PUBLIC;
GRANT EXECUTE  ON FUNCTION sec_dba.check_app()  TO PUBLIC;

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
