 

# 🛡️ PG-App-Check

**Auditoría de inicios de sesión en PostgreSQL y bloqueo de aplicaciones no autorizadas mediante `login_hook`.**

Controla qué aplicaciones cliente pueden conectarse a tus clústeres de PostgreSQL, audita cada evento de inicio de sesión y bloquea herramientas no autorizadas — todo sin tocar el archivo `pg_hba.conf` ni los firewalls de red.

## Tabla de Contenidos

  * [Problema](https://www.google.com/search?q=%23problema)
  * [Cómo Funciona](https://www.google.com/search?q=%23c%C3%B3mo-funciona)
  * [Arquitectura](https://www.google.com/search?q=%23arquitectura)
  * [Requisitos](https://www.google.com/search?q=%23requisitos)
  * [Inicio Rápido](https://www.google.com/search?q=%23inicio-r%C3%A1pido)
  * [Configuración](https://www.google.com/search?q=%23configuraci%C3%B3n)
      * [Bloqueo de Aplicaciones](https://www.google.com/search?q=%23bloqueo-de-aplicaciones)
      * [Exención de Usuarios](https://www.google.com/search?q=%23exenci%C3%B3n-de-usuarios)
  * [Log de Auditoría](https://www.google.com/search?q=%23log-de-auditor%C3%ADa)
  * [Consultas de Monitoreo](https://www.google.com/search?q=%23consultas-de-monitoreo)
  * [Mantenimiento](https://www.google.com/search?q=%23mantenimiento)
  * [Actualización desde v1](https://www.google.com/search?q=%23actualizaci%C3%B3n-desde-v1)
  * [Consideraciones de Seguridad](https://www.google.com/search?q=%23consideraciones-de-seguridad)
  * [Solución de Problemas](https://www.google.com/search?q=%23soluci%C3%B3n-de-problemas)
  * [Contribuciones](https://www.google.com/search?q=%23contribuciones)
  * [Licencia](https://www.google.com/search?q=%23licencia)

-----

## Problema

En muchas organizaciones, las credenciales de las bases de datos se comparten o se filtran, y los usuarios se conectan con herramientas GUI no autorizadas (DBeaver, Navicat, pgAdmin, etc.) que pueden saltarse los controles de acceso a nivel de aplicación, ejecutar consultas ad-hoc, exportar datos masivos o modificar esquemas. El archivo `pg_hba.conf` de PostgreSQL autentica usuarios pero no puede distinguir qué aplicación inició la conexión.

**PG-App-Check** soluciona esto interceptando cada evento de inicio de sesión, comparando el `application_name` reportado contra una lista de bloqueo configurable, y permitiendo o rechazando la conexión — mientras registra cada evento para auditoría y cumplimiento normativo.

-----

## Cómo Funciona

```text
Cliente conecta → PostgreSQL → se dispara login_hook → sec_dba.check_app()
                                                        │
                                         ┌──────────────┴──────────────┐
                                         │                             │
                               ¿App bloqueada?                  App permitida
                                         │                             │
                                   Log BLOCKED                   Log ALLOWED
                                 RAISE EXCEPTION             Conexión procede
                              (conexión rechazada)
```

1.  La extensión `login_hook` llama a `sec_dba.check_app()` antes de que la sesión se establezca por completo.
2.  La función verifica si el usuario que se conecta está exento (vía patrones regex en `sec_dba.exempt_users`).
3.  Si no está exento, verifica el `application_name` contra patrones `ILIKE` en `sec_dba.blocked_applications`.
4.  Cada evento (permitido o bloqueado) se escribe en `sec_dba.login_audit_log`.
5.  Las conexiones bloqueadas reciben un mensaje de error claro y la conexión se termina.

-----

## Arquitectura

**Esquema `sec_dba`**

  * `check_app()` — Función principal (llamada por `login_hook`).
  * `blocked_applications` — Config: Patrones `ILIKE` para bloquear.
  * `exempt_users` — Config: Patrones regex para usuarios exentos.
  * `login_audit_log` — Auditoría: cada evento de inicio de sesión.

### Decisiones de Diseño Clave (v2 vs v1)

| Aspecto | v1 (Original) | v2 (Actual) |
| :--- | :--- | :--- |
| **Registro (Logging)** | Archivos CSV vía `COPY TO PROGRAM` | Tabla de base de datos con índices |
| **Reglas de App** | Hardcoded en el cuerpo de la función | Tabla configurable (sin DDL para cambios) |
| **Exenciones de Usuario** | Regex hardcoded | Tabla configurable |
| **Manejo de Errores** | Ninguno (un bug podía bloquear a todos) | Bloque `EXCEPTION` ignora errores inesperados |
| **Seguridad** | Dueño: `pg_execute_server_program` | Dueño: `postgres` con `SECURITY DEFINER` |
| **Permisos** | Tablas de config abiertas a `PUBLIC` | Tablas restringidas; log de auditoría solo lectura |
| **Search Path** | Heredado (riesgo de inyección) | Fijado a `sec_dba, pg_catalog` |
| **Identificadores** | Hash `md5()` | UUID nativo vía `gen_random_uuid()` |

-----

## Requisitos

  * **PostgreSQL**: 12+ (usa `gen_random_uuid()`).
  * **login\_hook**: Cualquier versión estable.
  * **SO**: Linux (probado en RHEL 8/9, Ubuntu 20.04+, Debian 11+).

-----

## Inicio Rápido

### 1\. Instalar login\_hook

```bash
# Desde el código fuente
git clone https://github.com/splendiddata/login_hook.git
cd login_hook
make
make install
```

### 2\. Configurar PostgreSQL

Edita `postgresql.conf`:

```ini
shared_preload_libraries = 'login_hook'
login_hook.login = 'sec_dba.check_app'
```

### 3\. Instalar PG-App-Check

```bash
psql -U postgres -d tu_base_de_datos -f install.sql
```

### 4\. Reiniciar PostgreSQL

```bash
sudo systemctl restart postgresql
```

### 5\. Verificar

```bash
# Intenta conectar con un nombre de app bloqueado
PGAPPNAME="DBeaver 24.0" psql -U testuser -d tu_base_de_datos
# Esperado: ERROR — UNAUTHORIZED APPLICATION DETECTED

# Conectar con una app permitida
PGAPPNAME="myapp-backend" psql -U testuser -d tu_base_de_datos
# Esperado: Éxito
```

-----

## Configuración

### Bloqueo de Aplicaciones

Las reglas se guardan en `sec_dba.blocked_applications` y se comparan mediante `ILIKE` (insensible a mayúsculas).

```sql
-- Bloquear una nueva aplicación
INSERT INTO sec_dba.blocked_applications (app_pattern, description)
VALUES ('%pgAdmin%', 'pgAdmin no permitido en producción');

-- Desactivar temporalmente una regla
UPDATE sec_dba.blocked_applications
SET    is_active = FALSE
WHERE  app_pattern = '%pgAdmin%';
```

### Exención de Usuarios

Las exenciones son patrones regex comparados contra `session_user`:

```sql
-- Eximir una cuenta de admin específica
INSERT INTO sec_dba.exempt_users (username_pattern, description)
VALUES ('^dba_admin$', 'DBA admin — acceso sin restricciones');

-- Eximir todas las cuentas de servicio
INSERT INTO sec_dba.exempt_users (username_pattern, description)
VALUES ('^svc_', 'Cuentas de servicio omiten validación de app');
```

-----

## Log de Auditoría

Cada evento se registra en `sec_dba.login_audit_log`.

| Columna | Tipo | Descripción |
| :--- | :--- | :--- |
| `event_id` | UUID | Identificador único del evento |
| `event_type` | TEXT | `ALLOWED` o `BLOCKED` |
| `session_user_` | TEXT | Usuario que conecta |
| `application_name`| TEXT | Nombre de la aplicación reportado |
| `event_time` | TIMESTAMPTZ | Marca de tiempo del evento |

-----

## Consideraciones de Seguridad

### Lo que esto PROTEGE:

  * Usuarios conectándose con herramientas GUI no autorizadas.
  * Uso de "Shadow IT" de clientes de base de datos en producción.
  * Proporciona una traza de auditoría para cumplimiento (SOC 2, PCI-DSS, HIPAA).

### Lo que esto NO protege:

  * **Suplantación de `application_name`**: Un atacante sofisticado puede cambiar el nombre de la aplicación. Esta es una herramienta de cumplimiento de políticas, no una barrera criptográfica. Disuade el mal uso casual y da visibilidad.
  * **Conexiones antes de cargar el hook**: Si `shared_preload_libraries` está mal configurado, el hook no se ejecutará.
  * **Bypass de Superusuario**: Los superusuarios pueden alterar la función o desactivar el hook.

-----

## Estructura de Archivos

```text
pg-app-check/
├── README.md            # Este archivo
├── install.sql          # Script de instalación completa
├── uninstall.sql        # Eliminación completa
├── maintenance.sql      # Consultas de monitoreo y purga
└── LICENSE              # Licencia MIT
```

-----

**Aviso legal:** `application_name` es una cadena reportada por el cliente y puede ser suplantada. Esta herramienta proporciona cumplimiento de políticas y auditoría, no una garantía de seguridad criptográfica. Combine siempre con controles a nivel de red (`pg_hba.conf`, firewalls, VPNs).
 
