
-- DROP TABLE public.pg_hba;
CREATE TABLE public.pg_hba (
    id              SERIAL PRIMARY KEY,
    client_ip       CIDR NOT NULL DEFAULT '0.0.0.0/0',      -- Soporta IP única o rangos CIDR
    username_regex  text NOT NULL DEFAULT 'ALL',      -- Expresión regular para el usuario
    app_name_regex  text NOT NULL DEFAULT 'ALL',      -- Expresión regular para el nombre de la app
    rule_type       text NOT NULL CHECK (rule_type IN ('ALLOW', 'DENY')) DEFAULT 'DENY',
    is_blocking     boolean DEFAULT true,  -- true: RAISE EXCEPTION, false: RAISE NOTICE
    is_active       boolean DEFAULT true,    -- Permite habilitar/deshabilitar la regla
    error_msg       TEXT NOT NULL DEFAULT 'Política de seguridad aplicada, revise con el administrador',
    description     TEXT,
    created_at      timestamp with time zone DEFAULT now(),

    -- Esto evita que existan dos filas con la misma combinación de IP, Usuario y App.
    CONSTRAINT unique_access_rules UNIQUE (client_ip, username_regex, app_name_regex, rule_type)
);

 
-- Índices para mejorar la velocidad de búsqueda en cada login
-- drop INDEX idx_pg_hba_active;
CREATE INDEX idx_pg_hba_active ON public.pg_hba(is_active) WHERE is_active = true;

-- drop INDEX idx_unique_login_rules_insensitive ;
-- CREATE UNIQUE INDEX idx_unique_login_rules_insensitive ON public.pg_hba  (client_ip, (username_regex), (app_name_regex), rule_type );


-- Default blocked applications
/*
INSERT INTO public.pg_hba (app_name_regex, is_active , description,error_msg) VALUES
    ('pgAdmin'        ,true,    'pgAdmin — Herramienta GUI no autorizada',
    ' El usuario esta realizando una conexión a la base de datos desde una aplicación no autorizada. Esta acción está en violación de nuestras políticas de seguridad y no corresponde al propósito para el cual se creó el usuario. Si crees que este mensaje es un error, por favor contacta al equipo de DBA inmediatamente. ');
*/

INSERT INTO public.pg_hba (app_name_regex, is_active , description)
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


-- select id,client_ip,username_regex,app_name_regex,rule_type,is_blocking,is_active,description,created_at from  public.pg_hba;

 

-- DROP FUNCTION public.login();
CREATE OR REPLACE FUNCTION public.login()
returns event_trigger
SECURITY DEFINER
SET search_path = pg_catalog, public
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
    FROM public.pg_hba
    WHERE is_active = true 
      AND rule_type = 'ALLOW'
      AND (client_ip <<= '0.0.0.0/0' OR v_current_ip <<= client_ip)
      AND (username_regex = 'all' OR username_regex = 'ALL' OR v_current_user ~ username_regex)
      AND (app_name_regex = 'all' OR app_name_regex = 'ALL' OR v_current_app ~* app_name_regex)
    LIMIT 1;

    IF FOUND THEN
        -- Es un usuario exento, salimos de la función y permitimos el acceso
        RETURN;
    END IF;

    -- 3. SEGUNDA BÚSQUEDA: ¿Existe una regla de bloqueo (DENY)?
    -- Si no hubo exención, buscamos si hay algo que lo bloquee.
    SELECT * INTO v_rule
    FROM public.pg_hba
    WHERE is_active = true 
      AND rule_type = 'DENY'
      AND (client_ip <<= '0.0.0.0/0' OR v_current_ip <<= client_ip)
      AND (username_regex = 'all' OR username_regex = 'ALL' OR v_current_user ~ username_regex)
      AND (app_name_regex = 'all' OR app_name_regex = 'ALL' OR v_current_app ~* app_name_regex)
    --ORDER BY ( (client_ip IS NOT NULL)::int + (username_regex IS NOT NULL)::int + (app_name_regex IS NOT NULL)::int ) DESC
    LIMIT 1;
    -- El ORDER BY opcional prioriza reglas más específicas sobre las generales

    -- 4. Si se encontró un bloqueo, procedemos
    IF FOUND THEN
        --RAISE NOTICE  'Acceso Denegado!!!';
        RAISE WARNING 'Acceso restringido: Usuario: %, IP: %, App: %, Regla ID: %', v_current_user, v_current_ip, v_current_app, v_rule.id;

        
        IF v_rule.is_blocking THEN
	
          -- EXECUTE FORMAT(E'SELECT pg_terminate_backend(pg_backend_pid( /*\n\n %I \n\n*/ ));' , v_rule.error_msg);          
			RAISE EXCEPTION E'\n\n % \n\n' , v_rule.error_msg; -- El EXCEPTION en trigger funciona mejor que login_hook este bloque todo y no es como la extension que permite el acceso a los superuser.

        ELSE
            RAISE WARNING 'Aviso de seguridad: Su sesión está siendo monitoreada por políticas internas.';
        END IF;
    END IF;



END;
$$ LANGUAGE plpgsql;



-- Owner with minimal privileges (no superuser)
ALTER FUNCTION public.login() OWNER TO postgres;

-- All users must execute this function (login_hook calls it per-session)
GRANT EXECUTE  ON FUNCTION public.login()  TO PUBLIC;





-- DROP event trigger my_login_trg  ;
  create event trigger my_login_trg
  on login
  execute function public.login();
 



----------------------------------------------------------------------------------------------------------------
/*


-------- Nota importante : En caso de bloquear algo por accidente , solo ingresa a otra base de datos como la template1 y desactiva el parametro event_triggers y realiza reaload

-- Para desactivar los trigger en todo el cluster
alter system set event_triggers TO off;
select pg_reload_conf();



PGAPPNAME="pgadmin" psql -h localhost -U jose -d mi_base_de_datos
psql "postgresql://jose@localhost:5432/mi_base_de_datos?application_name=DBeaver"
psql "postgresql://jose@localhost:5432/mi_base_de_datos?application_name=DBeaver"

 pg_ctl reload -D $PGDATA12


select * from public.pg_hba;
update public.pg_hba set client_ip = '10.28.230.123'  where id = 34 ;


INSERT INTO public.pg_hba (client_ip, rule_type, is_blocking)  VALUES ('127.0.0.0/24', 'DENY', true);
INSERT INTO public.pg_hba (app_name_regex, rule_type, is_blocking)  VALUES ('^psql$', 'DENY', true);

INSERT INTO public.pg_hba (app_name_regex, rule_type, is_blocking, error_msg)  VALUES ('pgadmin', 'DENY', true, ' El usuario esta realizando una conexión a la base de datos desde una aplicación no autorizada. Esta acción está en violación de nuestras políticas de seguridad y no corresponde al propósito para el cual se creó el usuario. Si crees que este mensaje es un error, por favor contacta al equipo de DBA inmediatamente. ');



INSERT INTO public.pg_hba (client_ip, username_regex, rule_type)  VALUES ('127.0.0.1', '^postgres$', 'ALLOW'); 


INSERT INTO public.pg_hba (username_regex, rule_type, is_blocking)  VALUES ('^jose$', 'DENY', true);


INSERT INTO public.pg_hba (client_ip, username_regex, app_name_regex, rule_type, is_blocking)  VALUES ('127.0.0.1/32', '^jose$', '^psql$', 'DENY', true);


create user jose with password '123123';

PGPASSWORD=123123 psql -p 5412 -d test -h 10.28.230.123

PGAPPNAME="pgadmin" PGPASSWORD=123123 psql -p 5412 -d test -h 127.0.0.1 -U postgres
PGAPPNAME="pgadmin" PGPASSWORD=123123 psql -p 5412 -d test -h 127.0.0.1 -U jose


-- Limpiar reglas previas
TRUNCATE public.pg_hba;


postgres@test#
postgres@test# select * from  public.pg_hba;
+----+--------------+----------------+----------------+-----------+-------------+-----------+-------------------------------+
| id |  client_ip   | username_regex | app_name_regex | rule_type | is_blocking | is_active |          created_at           |
+----+--------------+----------------+----------------+-----------+-------------+-----------+-------------------------------+
|  2 | 127.0.0.1/32 | ^postgres$     | pgadmin        | ALLOW     | t           | t         | 2026-04-10 16:38:04.032428-07 |
|  1 | NULL         | NULL           | pgadmin        | DENY      | t           | t         | 2026-04-10 16:37:52.063594-07 |
+----+--------------+----------------+----------------+-----------+-------------+-----------+-------------------------------+
(2 rows)


-- Para deshabilitarlo
ALTER EVENT TRIGGER my_login_trg DISABLE;

-- Para volverlo a activar
ALTER EVENT TRIGGER my_login_trg ENABLE;


--- Indica que el trigger se ejecutará sin importar el rol de la sesión actual. session_replication_role
alter event trigger my_login_trg enable always;


SET session_replication_role = replica;

 */
----------------------------------------------------------------------
