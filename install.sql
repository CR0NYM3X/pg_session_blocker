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
CREATE TABLE IF NOT EXISTS sec_dba.exempt_users (
    id              SERIAL PRIMARY KEY,
    username_pattern TEXT       NOT NULL,            -- Regex pattern, e.g. '^(dba_|svc_)'
    description     TEXT,
    is_active       BOOLEAN    NOT NULL DEFAULT TRUE,
    enforce_blocking BOOLEAN    NOT NULL DEFAULT FALSE, -- Default: alerts only
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
    'Audit trail for all login events processed by sec_dba.login(). Partitioning by event_time is recommended for high-traffic clusters.';


-- ---------------------------------------------------------------------------
-- 5. MAIN FUNCTION: login()
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION login_hook.login()
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
    -- Nuevas variables de control
    v_log_success   BOOLEAN := FALSE;
    v_log_failure   BOOLEAN := TRUE;
    v_enforce       BOOLEAN := FALSE; 
BEGIN
    -- 1. Guard: Prevent manual invocation
    IF EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = pg_backend_pid()) THEN
        RAISE EXCEPTION 'sec_dba.login() is designed for login_hook only and cannot be invoked manually.';
    END IF;

    -- 2. Gather connection metadata
    v_server_ip   := inet_server_addr();
    v_client_ip   := inet_client_addr();
    v_server_port := inet_server_port();

    -- 3. Check if the user is exempt and get enforcement policy
    SELECT TRUE, enforce_blocking INTO v_is_exempt, v_enforce
    FROM sec_dba.exempt_users
    WHERE is_active
      AND v_session_user ~ username_pattern
    LIMIT 1;

    v_is_exempt := COALESCE(v_is_exempt, FALSE);
    v_enforce   := COALESCE(v_enforce, FALSE); -- Por defecto: Alerta solamente

    -- 4. Check if the application is in the blocked list and get log policies
    SELECT TRUE, ba.app_pattern, ba.log_on_success, ba.log_on_failure
      INTO v_is_blocked, v_matched_app, v_log_success, v_log_failure
    FROM sec_dba.blocked_applications ba
    WHERE ba.is_active
      AND v_app_name ILIKE ba.app_pattern
    LIMIT 1;

    v_is_blocked := COALESCE(v_is_blocked, FALSE);
    v_log_success := COALESCE(v_log_success, FALSE);
    v_log_failure := COALESCE(v_log_failure, TRUE);

    -- 5. Audit & Enforce
    IF v_is_blocked AND NOT v_is_exempt THEN
        -- Log blocked attempt (if policy allows)
        IF v_log_failure THEN
            INSERT INTO sec_dba.login_audit_log
                (event_type, server_ip, server_port, database_name,
                 session_user_, client_ip, application_name, message)
            VALUES
                ('BLOCKED', v_server_ip, v_server_port, v_database,
                 v_session_user, v_client_ip, v_app_name,
                 format('Blocked by pattern: %s', v_matched_app));
        END IF;

        -- Reject connection
        RAISE EXCEPTION E' \n\n El usuario: [%] esta realizando una conexión a la base de datos [%] desde la aplicación [%] no autorizada... \n\n ', v_session_user, v_database, v_app_name;

    ELSIF v_is_blocked AND v_is_exempt THEN
        -- Caso: Aplicación bloqueada pero el usuario es exento.
        IF NOT v_enforce THEN
            -- Solo alerta al usuario pero permite entrar
            RAISE NOTICE 'ALERTA DE SEGURIDAD: Su usuario posee una exención para utilizar [%], pero esta aplicación no es estándar.', v_app_name;
        END IF;
        
        -- Log success (if policy allows)
        IF v_log_success THEN
            INSERT INTO sec_dba.login_audit_log
                (event_type, server_ip, server_port, database_name,
                 session_user_, client_ip, application_name, message)
            VALUES
                ('ALLOWED_EXEMPT', v_server_ip, v_server_port, v_database,
                 v_session_user, v_client_ip, v_app_name,
                 'Connection authorized by user exemption');
        END IF;
    ELSE
        -- Log normal successful connection (if policy allows)
        -- Nota: Aquí v_log_success dependerá de si se encontró un patrón, 
        -- si no hay patrón de bloqueo, usualmente no logueamos a menos que sea necesario.
        IF v_log_success THEN
            INSERT INTO sec_dba.login_audit_log
                (event_type, server_ip, server_port, database_name,
                 session_user_, client_ip, application_name, message)
            VALUES
                ('ALLOWED', v_server_ip, v_server_port, v_database,
                 v_session_user, v_client_ip, v_app_name,
                 'Connection authorized');
        END IF;
    END IF;

EXCEPTION
    WHEN OTHERS THEN
        -- Re-raise blocking exceptions
        IF SQLERRM ILIKE '%no autorizada%' OR
           SQLERRM ILIKE '%login_hook only%' THEN
            RAISE;
        END IF;
        RAISE WARNING 'sec_dba.login() unexpected error (connection allowed): % — %',
                       SQLSTATE, SQLERRM;
END;
$$;




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
