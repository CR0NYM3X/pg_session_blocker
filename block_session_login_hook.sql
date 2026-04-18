

create EXTENSION login_hook ;

-- DROP TABLE login_hook.pg_hba;
CREATE TABLE login_hook.pg_hba (
    id              SERIAL PRIMARY KEY,
    client_ip       CIDR NOT NULL DEFAULT '0.0.0.0/0',      -- Soporta IP única o rangos CIDR
    username_regex  text NOT NULL DEFAULT 'ALL',      -- Expresión regular para el usuario
    app_name_regex  text NOT NULL DEFAULT 'ALL',      -- Expresión regular para el nombre de la app
    rule_type       text NOT NULL CHECK (rule_type IN ('ALLOW', 'DENY')) DEFAULT 'DENY',
    is_blocking     boolean DEFAULT true,  -- true: RAISE EXCEPTION, false: RAISE NOTICE
    is_active       boolean DEFAULT true,    -- Permite habilitar/deshabilitar la regla
	apply_on        TEXT NOT NULL DEFAULT 'all'  CHECK (apply_on IN ('all', 'primary', 'replica')),
	target_server   CIDR NOT NULL DEFAULT '0.0.0.0/0'
    error_msg       TEXT NOT NULL DEFAULT 'Política de seguridad aplicada, revise con el administrador',
    description     TEXT,
    created_at      timestamp with time zone DEFAULT now(),

    -- Esto evita que existan dos filas con la misma combinación de IP, Usuario y App.
    CONSTRAINT unique_access_rules UNIQUE (client_ip, username_regex, app_name_regex, rule_type)
);

-- Índices para mejorar la velocidad de búsqueda en cada login
CREATE INDEX idx_pg_hba_active ON login_hook.pg_hba(is_active) WHERE is_active = true;

-- DROP INDEX  login_hook.idx_unique_login_rules_insensitive;
-- CREATE UNIQUE INDEX idx_unique_login_rules_insensitive ON login_hook.pg_hba  (client_ip, (username_regex), (app_name_regex), rule_type );




-- Default blocked applications
/*
INSERT INTO login_hook.pg_hba (app_name_regex, is_active , description,error_msg) VALUES
    ('pgAdmin'        ,true,    'pgAdmin — Herramienta GUI no autorizada',
    ' El usuario esta realizando una conexión a la base de datos desde una aplicación no autorizada. Esta acción está en violación de nuestras políticas de seguridad y no corresponde al propósito para el cual se creó el usuario. Si crees que este mensaje es un error, por favor contacta al equipo de DBA inmediatamente. ');
*/

INSERT INTO login_hook.pg_hba (app_name_regex, is_active , description)
VALUES
    -- Herramientas de Administración (GUIs)
    ('DataGrip'         ,false,    'JetBrains DataGrip — Solo permitido en desarrollo'),
    ('HeidiSQL'         ,false,    'HeidiSQL — Cliente no autorizado'),
    ('SQLGate'          ,false,    'SQLGate — Cliente no autorizado'),
    ('TablePlus'        ,false,    'TablePlus — Cliente no autorizado'),
    ('Azure Data Studio',false,  'Azure Data Studio — Herramienta no autorizada'),
    ('DBeaver'          ,false,    'DBeaver IDE — not authorized for production'),
    ('Navicat'          ,false,    'Navicat — not authorized for production'),

    -- Herramientas de Análisis y BI (Shadow IT)
    -- Los usuarios de negocio conectan herramientas de visualización directamente a producción, lo que puede causar bloqueos o consumo excesivo de recursos
    ('Microsoft Office',false,   'MS Excel/Access — Riesgo de bloqueos por consultas pesadas'),
    ('PowerBI'        ,false,    'Power BI Desktop — Use réplicas de lectura, no producción'),
    ('Tableau'        ,false,    'Tableau — Use réplicas de lectura'),
    ('Qlik'           ,false,    'QlikView/QlikSense — Conexión directa no permitida'),

    -- Lenguajes de Scripting y Librerías
    -- forzar a que el acceso sea solo a través de la aplicación oficial y no mediante scripts
    ('python-requests',false,   'Scripts de Python (Requests) — Acceso no autorizado'),
    ('psycopg2'       ,false,   'Librería Psycopg2 directa — Use la App oficial'),
    ('node-postgres'  ,false,   'Node.js driver directo — Acceso no autorizado'),
    ('Go-http-client' ,false,   'Scripts en Go — Acceso no autorizado'),
    ('Java'           ,false,   'Aplicación Java genérica — No identificada'),

    -- Herramientas de Línea de Comandos (CLI)
    ('psql'           ,false,   'Psql — not authorized for production'),
    ('pg_dump'        ,false,   'pg_dump — Exportación de datos no autorizada por esta vía'),
    ('pg_restore'     ,false,   'pg_restore — Restauración no autorizada'),
    ('ogr2ogr'        ,false,   'GDAL/ogr2ogr — Herramienta de migración no autorizada');


-- select id,client_ip,username_regex,app_name_regex,rule_type,is_blocking,is_active,description,created_at from  login_hook.pg_hba;






-- DROP  FUNCTION login_hook.login();
CREATE OR REPLACE FUNCTION login_hook.login()
returns VOID
SECURITY DEFINER
SET search_path = login_hook, pg_catalog, public
SET client_min_messages = notice
AS $$
DECLARE
    v_rule RECORD;
    v_current_user text := session_user;
    v_current_ip   inet := inet_client_addr();
    -- Limpiamos el app_name para consistencia
    v_current_app  text := replace(lower(current_setting('application_name', true)), ' ', '');
    v_query        text;


    v_stack_context text;
    v_error_msg text;
    v_resultado int;

BEGIN

    -- 2. PRIMERA BÚSQUEDA: ¿Existe una excepción (ALLOW)?
    -- Si el usuario, IP y App coinciden con una regla ALLOW, ignoramos cualquier bloqueo.
    PERFORM 1 
    FROM login_hook.pg_hba
    WHERE is_active = true 
      AND rule_type = 'ALLOW'
      AND (client_ip <<= '0.0.0.0/0' OR v_current_ip <<= client_ip)
      AND (username_regex = 'all' OR username_regex = 'ALL' OR v_current_user ~ username_regex)
      AND (app_name_regex = 'all' OR app_name_regex = 'ALL' OR v_current_app ~* app_name_regex)
	  AND (apply_on = 'all'
	      OR (apply_on = 'primary' AND NOT pg_is_in_recovery())
	      OR (apply_on = 'replica'  AND pg_is_in_recovery()))
	  AND (target_server = '0.0.0.0' OR target_server = inet_server_addr())
    LIMIT 1;

    IF FOUND THEN
        -- Es un usuario exento, salimos de la función y permitimos el acceso
        RETURN;
    END IF;

    -- 3. SEGUNDA BÚSQUEDA: ¿Existe una regla de bloqueo (DENY)?
    -- Si no hubo exención, buscamos si hay algo que lo bloquee.
    SELECT * INTO v_rule
    FROM login_hook.pg_hba
    WHERE is_active = true 
      AND rule_type = 'DENY'
      AND (client_ip <<= '0.0.0.0/0' OR v_current_ip <<= client_ip)
      AND (username_regex = 'all' OR username_regex = 'ALL' OR v_current_user ~ username_regex)
      AND (app_name_regex = 'all' OR app_name_regex = 'ALL' OR v_current_app ~* app_name_regex)
	  AND (apply_on = 'all'
	      OR (apply_on = 'primary' AND NOT pg_is_in_recovery())
	      OR (apply_on = 'replica'  AND pg_is_in_recovery()))
	  AND (target_server = '0.0.0.0' OR target_server = inet_server_addr())		
    --ORDER BY ( (client_ip IS NOT NULL)::int + (username_regex IS NOT NULL)::int + (app_name_regex IS NOT NULL)::int ) DESC
    LIMIT 1;
    -- El ORDER BY opcional prioriza reglas más específicas sobre las generales

    -- 4. Si se encontró un bloqueo, procedemos
    IF FOUND THEN
        --RAISE NOTICE  'Acceso Denegado!!!';
        RAISE WARNING 'Acceso restringido: Usuario: %, IP: %, App: %, Regla ID: %', v_current_user, v_current_ip, v_current_app, v_rule.id;

        
        IF v_rule.is_blocking THEN
	
             EXECUTE FORMAT(E'SELECT pg_terminate_backend(pg_backend_pid( /*\n\n %I \n\n*/ ));' , v_rule.error_msg); -- usar este si quieres que aplique para todos no solo a usuarios que no son superuser          
			-- RAISE EXCEPTION E'\n\n % \n\n' , v_rule.error_msg; -- El EXCEPTION  con login_hook no hace efecto con los usuarios superuser esto por seguridad de la extension.

        ELSE
            RAISE WARNING 'Aviso de seguridad: Su sesión está siendo monitoreada por políticas internas.';
        END IF;
    END IF;



END;
$$ LANGUAGE plpgsql;

-- Owner with minimal privileges (no superuser)
ALTER FUNCTION login_hook.login() OWNER TO postgres;

-- All users must execute this function (login_hook calls it per-session)
GRANT USAGE    ON SCHEMA login_hook            TO PUBLIC;
GRANT EXECUTE  ON FUNCTION login_hook.login()  TO PUBLIC;




----------------------------------------------------------------------------------------------------------------
/*
Nota importante : En caso de bloquear algo por accidente , solo retira el nombre de login_hook en el parametro session_preload_libraries que se encuentra en el archivo postgresql.conf y realiza un reload en la base de datos y ya te dejeara ingresar. 


PGAPPNAME="pgadmin" psql -h localhost -U jose -d mi_base_de_datos
psql "postgresql://jose@localhost:5432/mi_base_de_datos?application_name=DBeaver"
psql "postgresql://jose@localhost:5432/mi_base_de_datos?application_name=DBeaver"

 pg_ctl reload -D $PGDATA12


select * from login_hook.pg_hba;
update login_hook.pg_hba set client_ip = '10.28.230.123'  where id = 34 ;


INSERT INTO login_hook.pg_hba (client_ip, rule_type, is_blocking)  VALUES ('127.0.0.0/24', 'DENY', true);
INSERT INTO login_hook.pg_hba (app_name_regex, rule_type, is_blocking)  VALUES ('^psql$', 'DENY', true);

INSERT INTO login_hook.pg_hba (app_name_regex, rule_type, is_blocking, error_msg)  VALUES ('pgadmin', 'DENY', true, ' El usuario esta realizando una conexión a la base de datos desde una aplicación no autorizada. Esta acción está en violación de nuestras políticas de seguridad y no corresponde al propósito para el cual se creó el usuario. Si crees que este mensaje es un error, por favor contacta al equipo de DBA inmediatamente. ');



INSERT INTO login_hook.pg_hba (client_ip, username_regex, rule_type)  VALUES ('127.0.0.1', '^postgres$', 'ALLOW');



INSERT INTO login_hook.pg_hba (username_regex, rule_type, is_blocking)  VALUES ('^jose$', 'DENY', true);


INSERT INTO login_hook.pg_hba (client_ip, username_regex, app_name_regex, rule_type, is_blocking)  VALUES ('127.0.0.1/32', '^jose$', '^psql$', 'DENY', true);


create user jose with password '123123';

PGPASSWORD=123123 psql -p 5412 -d test -h 10.28.230.123

PGAPPNAME="pgadmin" PGPASSWORD=123123 psql -p 5412 -d test -h 127.0.0.1 -U postgres
PGAPPNAME="pgadmin" PGPASSWORD=123123 psql -p 5412 -d test -h 127.0.0.1 -U jose


-- Limpiar reglas previas
TRUNCATE login_hook.pg_hba;


-- select name,setting from pg_settings where name ilike '%session_preload_libraries%';
+---------------------------+------------+
|           name            |  setting   |
+---------------------------+------------+
| session_preload_libraries | login_hook |
+---------------------------+------------+
(1 row)


postgres@test#
postgres@test# select * from  login_hook.pg_hba;
+----+--------------+----------------+----------------+-----------+-------------+-----------+-------------------------------+
| id |  client_ip   | username_regex | app_name_regex | rule_type | is_blocking | is_active |          created_at           |
+----+--------------+----------------+----------------+-----------+-------------+-----------+-------------------------------+
|  2 | 127.0.0.1/32 | ^postgres$     | pgadmin        | ALLOW     | t           | t         | 2026-04-10 16:38:04.032428-07 |
|  1 | NULL         | NULL           | pgadmin        | DENY      | t           | t         | 2026-04-10 16:37:52.063594-07 |
+----+--------------+----------------+----------------+-----------+-------------+-----------+-------------------------------+
(2 rows)


 */
----------------------------------------------------------------------
