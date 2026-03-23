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
CREATE OR REPLACE FUNCTION login_hook.login()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = sec_dba, pg_catalog, public
SET client_min_messages = notice
SET client_encoding = 'UTF-8'
AS $$
DECLARE
    -- Metadata básica
    v_app_name      TEXT    := replace(current_setting('application_name', true) , ' ', '');
    v_session_user  TEXT    := session_user;
    v_database      TEXT    := current_database();
    v_time_con      TIMESTAMP := CLOCK_TIMESTAMP();
    
    -- Metadata de red
    v_server_ip     INET;
    v_client_ip     INET;
    v_server_port   INT;
    
    -- Control de flujo
    v_is_restricted BOOLEAN := FALSE;
    v_is_app_blocked BOOLEAN := FALSE;
    v_matched_app   TEXT;
    v_enforce       BOOLEAN := FALSE; 
    v_log_success   BOOLEAN := FALSE;
    v_log_failure   BOOLEAN := TRUE;

    -- Variables para Logging en Archivo (Metodología COPY TO PROGRAM)
    v_query_exec    TEXT;
    v_path_log      TEXT := current_setting('data_directory') || '/' || current_setting('log_directory') || '/';
    v_file_failed   TEXT := 'unauthorized_app_users.csv';
    v_file_success  TEXT := 'authorized_app_users.csv';
BEGIN
    -- 1. Guard: Prevent manual invocation
    IF NOT login_hook.is_executing_login_hook() THEN
        RAISE EXCEPTION 'No puedes utilizar esta funcion, solo esta diseñada para el inicio de sesión';
    END IF;

    -- 2. VALIDACIÓN 1: ¿El usuario está en la LISTA NEGRA?
    SELECT TRUE, enforce_blocking INTO v_is_restricted, v_enforce
    FROM sec_dba.exempt_users 
    WHERE is_active
      AND v_session_user ~ username_pattern
    LIMIT 1;

    v_is_restricted := COALESCE(v_is_restricted, FALSE);
    v_enforce       := COALESCE(v_enforce, FALSE);

    -- 3. VALIDACIÓN 2: Si el usuario es restringido, chequeamos la aplicación
    IF v_is_restricted THEN
        SELECT TRUE, ba.app_pattern, ba.log_on_success, ba.log_on_failure
          INTO v_is_app_blocked, v_matched_app, v_log_success, v_log_failure
        FROM sec_dba.blocked_applications ba
        WHERE ba.is_active
          AND v_app_name ILIKE ba.app_pattern
        LIMIT 1;

        -- Gather connection metadata para el log
        v_server_ip   := inet_server_addr();
        v_client_ip   := inet_client_addr();
        v_server_port := inet_server_port();

        v_is_app_blocked := COALESCE(v_is_app_blocked, FALSE);
        v_log_success    := COALESCE(v_log_success, FALSE);
        v_log_failure    := COALESCE(v_log_failure, TRUE);

        -- 4. PERSISTENCIA EN ARCHIVO (Inmune al Rollback)
        IF v_is_app_blocked THEN
            IF v_log_failure THEN
                -- MÉTODO: Escritura directa a CSV usando UUID
                v_query_exec := format(E'COPY (SELECT gen_random_uuid(), %L, %L, %L, %L, %L, %L, %L, \'¡¡Bloqueo por Lista Negra!!\') TO PROGRAM \'cat >> %s%s\' WITH (FORMAT CSV);',
                                host(v_server_ip), v_server_port, v_database, v_session_user, host(v_client_ip), v_app_name, v_time_con, v_path_log, v_file_failed);
                EXECUTE v_query_exec;
            END IF;

            -- Aplicar Bloqueo (Genera Exception pero el archivo ya fue escrito)
            IF v_enforce THEN
                RAISE NOTICE E' \n\n El usuario: [%] esta realizando una conexión a la base de datos [%] desde la aplicación [%] no autorizada... \n\n ', v_session_user, v_database, v_app_name;
                RAISE EXCEPTION 'Security Policy Violation';
            ELSE
                RAISE NOTICE 'ALERTA DE SEGURIDAD: Usuario restringido detectado usando [%], pero el bloqueo no está activo.', v_app_name;
            END IF;

        ELSE
            -- Usuario restringido usando App autorizada
            IF v_log_success THEN
                v_query_exec := format(E'COPY (SELECT gen_random_uuid(), %L, %L, %L, %L, %L, %L, %L, \'Usuario restringido - App Permitida\') TO PROGRAM \'cat >> %s%s\' WITH (FORMAT CSV);',
                                host(v_server_ip), v_server_port, v_database, v_session_user, host(v_client_ip), v_app_name, v_time_con, v_path_log, v_file_success);
                EXECUTE v_query_exec;
            END IF;
        END IF;
    
    ELSE
        -- Caso: Usuario NO está en la lista negra
        -- (No se realiza acción para optimizar el login de usuarios autorizados)
    END IF;

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
