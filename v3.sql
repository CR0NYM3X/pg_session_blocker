
Proyecto login


BEGIN;

create EXTENSION login_hook ;


CREATE TABLE login_hook.pg_hba (
    id              SERIAL PRIMARY KEY,
    client_ip       CIDR ,      -- Soporta IP única o rangos CIDR
    username_regex  text ,      -- Expresión regular para el usuario
    app_name_regex  text ,      -- Expresión regular para el nombre de la app
    rule_type       text CHECK (rule_type IN ('ALLOW', 'DENY')) DEFAULT 'DENY',
    is_blocking     boolean DEFAULT true,  -- true: RAISE EXCEPTION, false: RAISE NOTICE
    is_active       boolean DEFAULT true,    -- Permite habilitar/deshabilitar la regla
    created_at      timestamp with time zone DEFAULT now(),

    -- Esto evita que existan dos filas con la misma combinación de IP, Usuario y App.
    CONSTRAINT unique_access_rule UNIQUE (client_ip, username_regex, app_name_regex)
);

-- Índices para mejorar la velocidad de búsqueda en cada login
CREATE INDEX idx_pg_hba_active ON login_hook.pg_hba(is_active) WHERE is_active = true;

-- DROP INDEX  login_hook.idx_unique_login_rules_insensitive;
CREATE UNIQUE INDEX idx_unique_login_rules_insensitive ON login_hook.pg_hba
 (client_ip, (username_regex), (app_name_regex), rule_type );



CREATE OR REPLACE FUNCTION login_hook.login()
RETURNS void
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
BEGIN

    -- 1. Seguridad: Solo ejecución vía hook (Asumiendo que esta función existe en tu entorno)
    IF NOT login_hook.is_executing_login_hook() THEN
        RAISE NOTICE 'No puedes utilizar esta funcion, solo esta diseñada para el inicio de sesión';
        --RETURN;
    END IF;

    -- 2. PRIMERA BÚSQUEDA: ¿Existe una excepción (ALLOW)?
    -- Si el usuario, IP y App coinciden con una regla ALLOW, ignoramos cualquier bloqueo.
    PERFORM 1 
    FROM login_hook.pg_hba
    WHERE is_active = true 
      AND rule_type = 'ALLOW'
      AND (client_ip IS NULL OR v_current_ip <<= client_ip)
      AND (username_regex IS NULL OR v_current_user ~ username_regex)
      AND (app_name_regex IS NULL OR v_current_app ~ app_name_regex)
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
      AND (client_ip IS NULL OR v_current_ip <<= client_ip)
      AND (username_regex IS NULL OR v_current_user ~ username_regex)
      AND (app_name_regex IS NULL OR v_current_app ~ app_name_regex)
    --ORDER BY ( (client_ip IS NOT NULL)::int + (username_regex IS NOT NULL)::int + (app_name_regex IS NOT NULL)::int ) DESC
    LIMIT 1;
    -- El ORDER BY opcional prioriza reglas más específicas sobre las generales

    -- 4. Si se encontró un bloqueo, procedemos
    IF FOUND THEN
        RAISE NOTICE 'Acceso Denegado!!!';
        RAISE WARNING 'Acceso restringido: Usuario: %, IP: %, App: %, Regla ID: %', v_current_user, v_current_ip, v_current_app, v_rule.id;

        
        IF v_rule.is_blocking THEN
          
          --v_query = FORMAT(E'SELECT pg_terminate_backend(pg_backend_pid()) /* % - % */;'  , v_current_user, v_current_app );
          --EXECUTE v_query;  -- este tumba a todas las conexiones sin importar si eres superusuario
          SELECT pg_terminate_backend(pg_backend_pid());
          --RAISE EXCEPTION ''; -- Este hace que los superusuarios pueda ingresar 
        ELSE
            RAISE WARNING 'Aviso de seguridad: Su sesión está siendo monitoreada por políticas internas.';
        END IF;
    END IF;
END;
$$ LANGUAGE plpgsql;


ROLLBACK;



----------------------------------------------------------------------------------------------------------------

PGAPPNAME="pgadmin" psql -h localhost -U jose -d mi_base_de_datos
psql "postgresql://jose@localhost:5432/mi_base_de_datos?application_name=DBeaver"
psql "postgresql://jose@localhost:5432/mi_base_de_datos?application_name=DBeaver"

 pg_ctl reload -D $PGDATA12


select * from login_hook.pg_hba;
update login_hook.pg_hba set client_ip = '10.28.230.123'  where id = 34 ;


INSERT INTO login_hook.pg_hba (client_ip, rule_type, is_blocking)  VALUES ('127.0.0.0/24', 'DENY', true);
INSERT INTO login_hook.pg_hba (app_name_regex, rule_type, is_blocking)  VALUES ('^psql$', 'DENY', true);

INSERT INTO login_hook.pg_hba (app_name_regex, rule_type, is_blocking)  VALUES ('^pg admin$', 'DENY', true);

INSERT INTO login_hook.pg_hba (client_ip, username_regex, rule_type)  VALUES ('127.0.0.1', '^postgres$', 'ALLOW');



INSERT INTO login_hook.pg_hba (username_regex, rule_type, is_blocking)  VALUES ('^jose$', 'DENY', true);


INSERT INTO login_hook.pg_hba (client_ip, username_regex, app_name_regex, rule_type, is_blocking)  VALUES ('127.0.0.1/32', '^jose$', '^psql$', 'DENY', true);


create user jose with password '123123';

PGPASSWORD=123123 psql -p 5412 -d test -h 10.28.230.123

PGAPPNAME="pgadmin" PGPASSWORD=123123 psql -p 5412 -d test -h 127.0.0.1 -U postgres
PGAPPNAME="pgadmin" PGPASSWORD=123123 psql -p 5412 -d test -h 127.0.0.1 -U jose


-- Limpiar reglas previas
TRUNCATE login_hook.pg_hba;


--  select name,setting from pg_settings where name ilike '%prelo%';

 
----------------------------------------------------------------------

