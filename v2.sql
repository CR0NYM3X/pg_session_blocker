
 
-- Cerrar session - Solo se puede usar COPY y EXCEPTION
-- Sin Cerrar sesion - se puede usar tabla para logs


drop database test_hook;
create database test_hook;
psql -p 5414 test_hook 
\dx

 create user "90196555";
psql -p 5414 -d test_hook -U 90196555



-- ============================================================================
-- pg-login-guard: PostgreSQL Login Auditing & Application Control
-- Version: 2.0.0
-- Requires: PostgreSQL 12+ | Extension: login_hook
-- ============================================================================


-- ---------------------------------------------------------------------------
-- 2. CONFIGURATION TABLE: Blocked applications (replaces hardcoded patterns)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS login_hook.blocked_applications (
    id              SERIAL PRIMARY KEY,
    app_pattern     TEXT        NOT NULL,
    description     TEXT,
    is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
    block           BOOLEAN     NOT NULL DEFAULT FALSE, 
    log_on_success  BOOLEAN     NOT NULL DEFAULT FALSE,
    log_on_failure  BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      TEXT        NOT NULL DEFAULT current_user
);



COMMENT ON TABLE login_hook.blocked_applications IS
    'Applications blocked from connecting. Patterns are matched with ILIKE against application_name.';


-- Default blocked applications
INSERT INTO login_hook.blocked_applications (app_pattern, is_active , description)
VALUES
    -- Herramientas de Administración (GUIs)
    ('%pgAdmin%',true,      'pgAdmin — Herramienta GUI no autorizada'),
    ('%DataGrip%',true,     'JetBrains DataGrip — Solo permitido en desarrollo'),
    ('%HeidiSQL%',true,     'HeidiSQL — Cliente no autorizado'),
    ('%SQLGate%',true,      'SQLGate — Cliente no autorizado'),
    ('%TablePlus%',true,    'TablePlus — Cliente no autorizado'),
    ('%Azure Data Studio%',true, 'Azure Data Studio — Herramienta no autorizada'),
    ('%DBeaver%',true,       'DBeaver IDE — not authorized for production'),
    ('%Navicat%',true,       'Navicat — not authorized for production'),

    -- Herramientas de Análisis y BI (Shadow IT)
    -- Los usuarios de negocio conectan herramientas de visualización directamente a producción, lo que puede causar bloqueos o consumo excesivo de recursos
    ('%Microsoft Office%',true, 'MS Excel/Access — Riesgo de bloqueos por consultas pesadas'),
    ('%PowerBI%',true,          'Power BI Desktop — Use réplicas de lectura, no producción'),
    ('%Tableau%',true,          'Tableau — Use réplicas de lectura'),
    ('%Qlik%',true,             'QlikView/QlikSense — Conexión directa no permitida'),

    -- Lenguajes de Scripting y Librerías
    -- forzar a que el acceso sea solo a través de la aplicación oficial y no mediante scripts
    ('%python-requests%',false, 'Scripts de Python (Requests) — Acceso no autorizado'),
    ('%psycopg2%', false,       'Librería Psycopg2 directa — Use la App oficial'),
    ('%node-postgres%',false,    'Node.js driver directo — Acceso no autorizado'),
    ('%Go-http-client%',false,   'Scripts en Go — Acceso no autorizado'),
    ('%Java%', false,            'Aplicación Java genérica — No identificada'),

    -- Herramientas de Línea de Comandos (CLI)
    ('%psql%',true,          'Psql — not authorized for production'),
    ('%pg_dump%',false,   'pg_dump — Exportación de datos no autorizada por esta vía'),
    ('%pg_restore%',false, 'pg_restore — Restauración no autorizada'),
    ('%ogr2ogr%',false,   'GDAL/ogr2ogr — Herramienta de migración no autorizada')

ON CONFLICT DO NOTHING;

select * from login_hook.blocked_applications ;

-- ---------------------------------------------------------------------------
-- 3. CONFIGURATION TABLE: Exempt users (service accounts, DBAs, etc.)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS login_hook.blocked_users (
    id               SERIAL PRIMARY KEY,
    app_id           INT REFERENCES login_hook.blocked_applications(id), -- Llave Foránea
    username_pattern TEXT        NOT NULL,
    description      TEXT,
    is_active        BOOLEAN     NOT NULL DEFAULT TRUE,
    block            BOOLEAN     NOT NULL DEFAULT FALSE,
    log_on_success   BOOLEAN     NOT NULL DEFAULT FALSE,
    log_on_failure   BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by       TEXT        NOT NULL DEFAULT current_user
);

COMMENT ON TABLE login_hook.blocked_users IS
    'Users exempt from application checks. Patterns matched with ~ (regex) against session_user.';


-- Default exempt pattern: users whose name starts with a digit (legacy behavior)
INSERT INTO login_hook.blocked_users (app_id,username_pattern, description)
VALUES
    (18,'^[0-9]', 'Numeric-prefixed service accounts')
ON CONFLICT DO NOTHING;


-- truncate table login_hook.blocked_users RESTART IDENTITY ;
select * from login_hook.blocked_users ;


-- ---------------------------------------------------------------------------
-- 4. AUDIT LOG TABLE: Replaces CSV files — queryable, indexable, rotatable
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS login_hook.login_audit_log (
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
    ON login_hook.login_audit_log (event_time DESC);

CREATE INDEX IF NOT EXISTS idx_login_audit_user
    ON login_hook.login_audit_log (session_user_);

CREATE INDEX IF NOT EXISTS idx_login_audit_type
    ON login_hook.login_audit_log (event_type)
    WHERE event_type = 'BLOCKED';

COMMENT ON TABLE login_hook.login_audit_log IS
    'Audit trail for all login events processed by login_hook.login(). Partitioning by event_time is recommended for high-traffic clusters.';

 
select * from login_hook.login_audit_log ;




 
--- cat /sysx/data14/pg_log/login_guard_activity.csv




 
--- cat /sysx/data14/pg_log/login_guard_activity.csv




CREATE OR REPLACE FUNCTION login_hook.login()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = login_hook, pg_catalog, public
SET client_min_messages = notice
SET client_encoding = 'UTF-8'
AS $$
DECLARE
    -- Metadata
    v_app_name       TEXT      := replace(current_setting('application_name', true) , ' ', '');
    v_session_user   TEXT      := session_user;
    v_database       TEXT      := current_database();
    v_time_con       TIMESTAMP := CLOCK_TIMESTAMP();
    v_server_ip      INET      := inet_server_addr();
    v_client_ip      INET      := inet_client_addr();
    v_server_port    INT       := inet_server_port();
    
    -- Variables de Control de Regla
    v_rule_found     BOOLEAN := FALSE;
    v_is_active      BOOLEAN := TRUE; -- Nueva variable para el control de salida
    v_enforce_block  BOOLEAN;
    v_log_success    BOOLEAN;
    v_log_failure    BOOLEAN;
    v_rule_desc      TEXT;

    -- Logging
    v_query_exec     TEXT;
    v_path_log       TEXT := current_setting('data_directory') || '/' || current_setting('log_directory') || '/';
    -- Archivo único para registros vía COPY
    v_log_file_name  TEXT := 'login_guard_activity.csv';
BEGIN

        INSERT INTO login_hook.blocked_applications (app_pattern, description, is_active, block, log_on_success, log_on_failure)
                VALUES ('%DBeaver%', 'Acceso desde DBeaver IDE', true, true, true, true);

    -- 1. Seguridad: Solo ejecución vía hook
    IF NOT login_hook.is_executing_login_hook() THEN
        RAISE NOTICE 'No puedes utilizar esta funcion de forma manual.';
    END IF;

    -- 2. PRIMER PASO: Buscar en la tabla de USUARIOS (incluyendo el filtro de la App asociada)
    -- Se corrige el INTO: el último valor de la tabla (is_active) ahora va a v_is_active
    SELECT TRUE, u.block, u.log_on_success, u.log_on_failure, u.description, u.is_active
    INTO v_rule_found, v_enforce_block, v_log_success, v_log_failure, v_rule_desc, v_is_active
    FROM login_hook.blocked_users u
    JOIN login_hook.blocked_applications a ON u.app_id = a.id
    WHERE v_session_user ~ u.username_pattern 
      AND v_app_name ILIKE a.app_pattern
    LIMIT 1;
        
    -- Si el usuario está registrado pero NO está activo, salimos de la función inmediatamente
    IF v_rule_found IS TRUE AND v_is_active IS FALSE THEN
        RETURN;
    END IF;
         
    -- 3. SEGUNDO PASO: Si no se encontró regla de usuario, buscar en la tabla de APLICACIONES
    IF NOT v_rule_found THEN
        SELECT TRUE, block, log_on_success, log_on_failure, description, is_active
        INTO v_rule_found, v_enforce_block, v_log_success, v_log_failure, v_rule_desc, v_is_active
        FROM login_hook.blocked_applications
        WHERE v_app_name ILIKE app_pattern
        LIMIT 1;
        
        -- Si la aplicación se encontró pero no está activa, salimos
        IF v_rule_found IS TRUE AND v_is_active IS FALSE THEN
            RETURN;
        END IF;
    END IF;
         
    -- 4. PROCESAR RESULTADO DE LA REGLA
    IF v_rule_found THEN
         RAISE NOTICE '444';
        -- Escenario A: SE DEBE BLOQUEAR (block = TRUE) -> Registro en ARCHIVO
        IF v_enforce_block THEN
            IF v_log_failure THEN
                v_query_exec := format(E'COPY (SELECT gen_random_uuid(), %L, %L, %L, %L, %L, %L, %L) TO PROGRAM \'cat >> %s%s\' WITH (FORMAT CSV);',
                    host(v_server_ip), v_server_port, v_database, v_session_user, host(v_client_ip), v_app_name, v_time_con, v_path_log, v_log_file_name);
                EXECUTE v_query_exec;
            END IF;
            
            RAISE NOTICE    'Acceso Denegado por Política de Seguridad: %', v_rule_desc;
            RAISE EXCEPTION '';

        -- Escenario B: SOLO AUDITAR/ADVERTIR (block = FALSE) -> Registro en TABLA
        ELSE
            IF v_log_success THEN
                -- Log en Tabla de Auditoría (Persiste porque no hay Exception)
                INSERT INTO login_hook.login_audit_log (event_type, server_ip, server_port, database_name, session_user_, client_ip, application_name)
                VALUES ('ALLOWED', v_server_ip, v_server_port, v_database, v_session_user, v_client_ip, v_app_name ); 
            END IF;
            
            RAISE NOTICE 'Aviso de Seguridad: Conexión registrada desde aplicación restringida (%).', v_app_name;
        END IF;
    END IF;

EXCEPTION 
    WHEN OTHERS THEN
        -- Si el error fue un RAISE EXCEPTION intencional (bloqueo), lo relanzamos
        IF SQLSTATE = 'P0001' THEN 
            RAISE EXCEPTION '%', SQLERRM;
        END IF;
        -- Para cualquier otro error inesperado, emitimos un aviso pero permitimos el login por seguridad
        RAISE WARNING 'Error interno en login_hook: %. Acceso permitido por política de seguridad (Fail-Open).', SQLERRM;
END;
$$;
 

 

--- Regresar al usuario original (solo superusuario puede hacerlo)


SET SESSION AUTHORIZATION  "90196555";
select * from login_hook.login();

RESET SESSION AUTHORIZATION ; 

/*
 update login_hook.blocked_users set block= true;

-- Activamos el log de éxito para los usuarios numéricos (como el 90196555)
UPDATE login_hook.blocked_users  SET log_on_success = true  WHERE id = 1;

*/
-- truncate table login_hook.login_audit_log RESTART IDENTITY ;
select * from login_hook.login_audit_log;






-- ---------------------------------------------------------------------------
-- 6. OWNERSHIP & PERMISSIONS
-- ---------------------------------------------------------------------------

-- Owner with minimal privileges (no superuser)
ALTER FUNCTION login_hook.login() OWNER TO postgres;

-- All users must execute this function (login_hook calls it per-session)
GRANT USAGE    ON SCHEMA login_hook                TO PUBLIC;
GRANT EXECUTE  ON FUNCTION login_hook.login()  TO PUBLIC;

-- Only DBAs should modify configuration tables
REVOKE ALL ON login_hook.blocked_applications FROM PUBLIC;
REVOKE ALL ON login_hook.blocked_users          FROM PUBLIC;
REVOKE ALL ON login_hook.login_audit_log       FROM PUBLIC;



-- ---------------------------------------------------------------------------
-- 7. CONFIGURE login_hook TO CALL THIS FUNCTION
-- ---------------------------------------------------------------------------
-- Add to postgresql.conf:
--   shared_preload_libraries = 'login_hook'
--   login_hook.login = 'login_hook.check_app'
-- Then: SELECT pg_reload_conf();  (or restart PostgreSQL)

DO $$
BEGIN
    RAISE NOTICE E'\n============================================================';
    RAISE NOTICE '  pg-login-guard installed successfully!';
    RAISE NOTICE '  ';
    RAISE NOTICE '  Next steps:';
    RAISE NOTICE '  1. Add to postgresql.conf:';
    RAISE NOTICE '     shared_preload_libraries = ''login_hook''';
    RAISE NOTICE '     login_hook.login = ''login_hook.check_app''';
    RAISE NOTICE '  2. Restart PostgreSQL';
    RAISE NOTICE '  3. Customize blocked apps:';
    RAISE NOTICE '     INSERT INTO login_hook.blocked_applications (app_pattern, description)';
    RAISE NOTICE '     VALUES (''%%pgAdmin%%'', ''pgAdmin blocked'');';
    RAISE NOTICE E'============================================================\n';
END;
$$;
