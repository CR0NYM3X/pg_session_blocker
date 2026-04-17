<p align="center">
  <img src="https://img.shields.io/badge/PostgreSQL-12%2B-336791?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL 12+"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/Security-Access%20Control-red?style=for-the-badge&logo=shield" alt="Security"/>
</p>

# 🛡️ pg_session_blocker

**Control de acceso dinámico para PostgreSQL — sin reinicios, sin editar archivos, sin downtime.**

`pg_session_blocker` te permite bloquear o permitir conexiones a tu base de datos en tiempo real, filtrando por **IP**, **usuario** y **aplicación**, todo desde una simple tabla SQL.

---

## ❓ ¿Qué problema resuelve?

El archivo `pg_hba.conf` de PostgreSQL es estático: cada cambio requiere editar el archivo y recargar la configuración. En entornos **Cloud SQL**, **réplicas de lectura** o infraestructuras con acceso limitado al sistema operativo, esto se vuelve un problema real.

**pg_session_blocker** mueve ese control a una tabla dentro de la base de datos, dándote flexibilidad total:

| Escenario | Sin pg_session_blocker | Con pg_session_blocker |
|:---|:---|:---|
| Bloquear una IP sospechosa | Editar `pg_hba.conf` + reload | Un `INSERT` y listo |
| Prohibir pgAdmin en producción | Imposible con `pg_hba.conf` | Una regla por `app_name` |
| Restringir `pg_dump` al nodo primario | Reglas de firewall externas | Una regla `DENY` en la tabla |
| Auditar sin bloquear | No disponible | Modo `is_blocking = false` |
| Cambios en Cloud SQL (sin acceso a archivos) | Ticket al proveedor | Control total desde SQL |

  **Control por Rol de Servidor (Primary/Replica):** Permite crear reglas que solo aplican en el nodo Primario o en las Réplicas , incluso puedes especificar IP de servidor

---

## 🏗️ ¿Cómo funciona?

Cuando un usuario se conecta, `pg_session_blocker` intercepta la sesión y evalúa las reglas en este orden:

```
   ┌─────────────────────────────┐
   │   Usuario intenta conectar  │
   └──────────────┬──────────────┘
                  ▼
   ┌─────────────────────────────┐
   │  ¿Existe regla ALLOW        │
   │  que coincida con IP,        │
   │  usuario y app?              │
   └──────────┬──────────────────┘
              │
         Sí ──┤──── No
              │         │
              ▼         ▼
   ┌──────────────┐  ┌─────────────────────────────┐
   │  ✅ PERMITIR  │  │  ¿Existe regla DENY          │
   │  acceso       │  │  que coincida?               │
   └──────────────┘  └──────────┬──────────────────┘
                               │
                          Sí ──┤──── No
                               │         │
                               ▼         ▼
                    ┌──────────────┐  ┌──────────────┐
                    │  🔒 BLOQUEAR  │  │  ✅ PERMITIR  │
                    │  o AVISAR     │  │  acceso       │
                    └──────────────┘  └──────────────┘
```

> **Regla clave:** Las reglas `ALLOW` siempre se evalúan primero. Si un usuario tiene una excepción, nunca será bloqueado.

---

## 🚀 Instalación Rápida

### Paso 1 — Elige tu método según la versión de PostgreSQL

| Versión | Método | Archivo |
|:---|:---|:---|
| **PostgreSQL 12 – 16** | Extensión `login_hook` | `block_session_login_hook.sql` |
| **PostgreSQL 17+** | Event Trigger nativo (`ON LOGIN`) | `block_session_trigger.sql` |

### Paso 2 — Ejecuta el script

#### Opción A: PostgreSQL 12 – 16 (login_hook)

```bash
# 1. Instala la extensión login_hook en tu servidor
# 2. Configura postgresql.conf:
#    session_preload_libraries = 'login_hook'
# 3. Recarga la configuración:
pg_ctl reload -D $PGDATA

# 4. Ejecuta el script SQL:
psql -d tu_base_de_datos -f block_session_login_hook.sql
```

#### Opción B: PostgreSQL 17+ (Event Trigger)

```bash
# No requiere extensiones externas
psql -d tu_base_de_datos -f block_session_trigger.sql
```

### Paso 3 — Verifica la instalación

```sql
-- Deberías ver la tabla con las reglas precargadas (todas desactivadas por defecto)
SELECT id, app_name_regex, rule_type, is_active, description
FROM pg_hba
ORDER BY id;
```

> **📌 Nota:** Todas las reglas vienen desactivadas (`is_active = false`). Actívalas según tus necesidades.

---

## 📊 Estructura de la tabla `pg_hba`

| Columna | Tipo | Default | Descripción |
|:---|:---|:---|:---|
| `client_ip` | `CIDR` | `0.0.0.0/0` | IP o rango de red. Ej: `10.0.0.1/32` para una IP, `10.0.0.0/24` para un segmento |
| `username_regex` | `TEXT` | `ALL` | Expresión regular del usuario. Ej: `^jose$` para un usuario exacto |
| `app_name_regex` | `TEXT` | `ALL` | Expresión regular de la aplicación. Ej: `pgadmin`, `^pg_dump$` |
| `rule_type` | `TEXT` | `DENY` | `ALLOW` para permitir, `DENY` para bloquear |
| `is_blocking` | `BOOL` | `true` | `true` = desconecta al usuario. `false` = solo emite un aviso (modo auditoría) |
| `is_active` | `BOOL` | `true` | Permite activar/desactivar reglas sin eliminarlas |
| `error_msg` | `TEXT` | *(mensaje genérico)* | Mensaje personalizado que verá el usuario bloqueado |
| `apply_on` | **TEXT** | Rol de servidor donde aplica la regla: `all` (default), `primary` o `replica`. Usa `pg_is_in_recovery()` internamente, por lo que sobrevive a failovers. |
| `target_server` | **CIDR** | IP del servidor específico donde aplica la regla. `0.0.0.0` (default) = cualquier servidor. Uso avanzado para topologías con múltiples réplicas. |
| `description` | `TEXT` | `NULL` | Nota interna para documentar el propósito de la regla |

---

## 📖 Ejemplos de Uso

### Bloquear una aplicación específica

```sql
-- Bloquear pgAdmin para todos los usuarios
INSERT INTO pg_hba (app_name_regex, rule_type, is_blocking, error_msg)
VALUES ('pgadmin', 'DENY', true,
  'Conexión rechazada: pgAdmin no está autorizado. Contacte al equipo de DBA.');
```

### Bloquear un rango de IPs

```sql
-- Bloquear toda la red 192.168.1.x
INSERT INTO pg_hba (client_ip, rule_type, is_blocking)
VALUES ('192.168.1.0/24', 'DENY', true);
```

### Bloquear un usuario específico

```sql
-- Bloquear al usuario "jose" desde cualquier origen
INSERT INTO pg_hba (username_regex, rule_type, is_blocking)
VALUES ('^jose$', 'DENY', true);
```

### Crear una excepción (ALLOW)

```sql
-- Permitir que el usuario "postgres" acceda desde localhost aunque existan reglas DENY
INSERT INTO pg_hba (client_ip, username_regex, rule_type)
VALUES ('127.0.0.1', '^postgres$', 'ALLOW');
```

### Combinar múltiples filtros

```sql
-- Bloquear al usuario "jose" solo cuando usa psql desde la IP 127.0.0.1
INSERT INTO pg_hba (client_ip, username_regex, app_name_regex, rule_type, is_blocking)
VALUES ('127.0.0.1/32', '^jose$', '^psql$', 'DENY', true);
```

### Modo auditoría (monitorear sin bloquear)

```sql
-- Registrar un aviso cuando alguien use pg_dump, sin desconectarlo
INSERT INTO pg_hba (app_name_regex, rule_type, is_blocking)
VALUES ('pg_dump', 'DENY', false);
```

### Forzar backups solo en la réplica

```sql
-- Bloquear pg_dump en el nodo primario
INSERT INTO pg_hba (app_name_regex, rule_type, error_msg)
VALUES ('pg_dump', 'DENY',
  'ACCESO DENEGADO: Realice los backups en la RÉPLICA (puerto 5433), no en producción.');
```

---

## 🔥 Caso práctico: Control de cuentas de servicio

Un escenario real donde las cuentas de servicio de aplicaciones solo deben conectarse desde su aplicación oficial, nunca desde herramientas externas como pgAdmin:

```sql
-- 1. Bloquear pgAdmin para todos los usuarios que empiecen con letra (cuentas de servicio)
INSERT INTO pg_hba (username_regex, app_name_regex, rule_type, is_blocking, error_msg, description)
VALUES (
  '^[^0-9].*',        -- Usuarios que empiezan con letra
  'pgadmin',
  'DENY', true,
  'Acceso denegado: Este usuario es de uso exclusivo del aplicativo oficial. Contacte al equipo de DBA.',
  'Bloqueo de cuentas de servicio en herramientas no autorizadas'
);

-- 2. Excepción: usuarios operativos "sys" + número de empleado pueden usar pgAdmin
INSERT INTO pg_hba (username_regex, app_name_regex, rule_type, description)
VALUES (
  '^sys[0-9].*',       -- Ej: sys521456
  'pgadmin',
  'ALLOW',
  'Excepción: usuarios operativos sys con número de empleado'
);
```

**Resultado:**
| Usuario | Herramienta | Resultado |
|:---|:---|:---|
| `user_app` | pgAdmin | 🔒 Bloqueado (empieza con letra) |
| `sys521456` | pgAdmin | ✅ Permitido (excepción `sys` + número) |
| `system` | pgAdmin | 🔒 Bloqueado (`sys` sin número después) |
| `12345` | pgAdmin | ✅ Permitido (empieza con número, no coincide con la regla) |



###  Bloquear `pg_dump` solo en el Primario (apply\_on)

En arquitecturas con **streaming replication**, un `DENY pg_dump` se replica vía WAL a las Réplicas, bloqueando backups en todos los nodos. Con `apply_on = 'primary'`, la regla solo se activa en el Primario — las Réplicas la ignoran porque `pg_is_in_recovery()` devuelve `true`.

```sql
INSERT INTO public.pg_hba (app_name_regex, rule_type, apply_on, error_msg)
VALUES ('pg_dump', 'DENY', 'primary', 
  'ACCESO DENEGADO: Los backups deben ejecutarse en la RÉPLICA (Puerto 5433 o 5434), no en producción.');
```

| Valor de `apply_on` | Comportamiento |
| :--- | :--- |
| `all` | La regla aplica en **todos** los nodos (default). |
| `primary` | Solo aplica en el nodo Primario (`pg_is_in_recovery() = false`). |
| `replica` | Solo aplica en nodos Réplica (`pg_is_in_recovery() = true`). |

> **📌 Nota sobre failover:** Si una Réplica se promueve a Primario, `pg_is_in_recovery()` cambia automáticamente a `false` y las reglas con `apply_on = 'primary'` comienzan a aplicar en el nuevo Primario sin intervención manual.

###  Restringir Réplicas exclusivamente para Reporting y Backups

Bloquea todo acceso en las Réplicas excepto las herramientas autorizadas.

```sql
-- Bloqueo general en réplicas
INSERT INTO public.pg_hba (rule_type, apply_on, error_msg)
VALUES ('DENY', 'replica', 'Las réplicas son exclusivas para reporting y backups.');

-- Excepciones: herramientas de BI y backups
INSERT INTO public.pg_hba (app_name_regex, rule_type, apply_on)
VALUES ('PowerBI|Tableau|pg_dump', 'ALLOW', 'replica');
```

###  Bloquear herramientas GUI solo en Producción (Primario)

Permite que los DBAs usen pgAdmin libremente en las Réplicas para consultas de lectura, pero lo bloquea en el Primario.

```sql
INSERT INTO public.pg_hba (app_name_regex, rule_type, apply_on, error_msg)
VALUES ('pgadmin|DBeaver', 'DENY', 'primary', 
  'Herramientas GUI no autorizadas en producción. Use la réplica para consultas de lectura.');
```

###  Uso Avanzado: `target_server` para Réplicas Específicas

Si tu topología tiene múltiples réplicas con roles distintos (ej. una para BI y otra para backups), puedes combinar `apply_on` con `target_server` para aplicar reglas a un servidor en particular por su IP.

```sql
-- Permitir Tableau SOLO en la réplica de BI (10.0.0.3)
INSERT INTO public.pg_hba (app_name_regex, rule_type, apply_on, target_server)
VALUES ('Tableau', 'ALLOW', 'replica', '10.0.0.3');

-- Permitir pg_dump SOLO en la réplica de backups (10.0.0.4)
INSERT INTO public.pg_hba (app_name_regex, rule_type, apply_on, target_server)
VALUES ('pg_dump', 'ALLOW', 'replica', '10.0.0.4');
```




> **📌 Nota:** requiere intervencion humana en caso de un failover, `target_server` usa `0.0.0.0` por default, lo que significa "cualquier servidor". Solo necesitas especificarlo cuando quieras distinguir entre réplicas individuales. Para la mayoría de los casos, `apply_on` es suficiente. 



---

## 🆘 Recuperación de Emergencia

Si accidentalmente te bloqueas a ti mismo, sigue estos pasos según tu método:

### PostgreSQL 12 – 16 (login_hook)

```bash
# 1. Edita postgresql.conf y comenta o elimina la línea:
#    session_preload_libraries = 'login_hook'

# 2. Recarga la configuración (no requiere reinicio):
pg_ctl reload -D $PGDATA

# 3. Ahora puedes conectarte y corregir las reglas:
psql -d tu_base_de_datos
# > TRUNCATE login_hook.pg_hba;  -- o elimina la regla problemática
```

### PostgreSQL 17+ (Event Trigger)

```bash
# 1. Conéctate a otra base de datos (ej: template1):
psql -d template1

# 2. Desactiva los event triggers a nivel de cluster:
ALTER SYSTEM SET event_triggers TO off;
SELECT pg_reload_conf();

# 3. Ahora conéctate a tu base y corrige las reglas:
psql -d tu_base_de_datos
# > TRUNCATE public.pg_hba;  -- o elimina la regla problemática

# 4. Reactiva los event triggers:
ALTER SYSTEM RESET event_triggers;
SELECT pg_reload_conf();
```

> **⚠️ Alternativa rápida para Event Trigger:**
> ```sql
> -- Deshabilitar solo el trigger sin tocar reglas globales
> ALTER EVENT TRIGGER my_login_trg DISABLE;
>
> -- Reactivar cuando termines:
> ALTER EVENT TRIGGER my_login_trg ENABLE;
> ```

---















## ⚖️ Diferencias entre los dos métodos

| Característica | login_hook (PG 12–16) | Event Trigger (PG 17+) |
|:---|:---|:---|
| Requiere extensión externa | ✅ Sí (`login_hook`) | ❌ No, es nativo |
| Bloquea superusuarios | ✅ Sí (usa `pg_terminate_backend`) | ✅ Sí (usa `RAISE EXCEPTION`) |
| Esquema de la tabla | `login_hook.pg_hba` | `public.pg_hba` |
| Configuración requerida | `session_preload_libraries` en `postgresql.conf` | Ninguna |
| Método de desactivación | Remover de `session_preload_libraries` + reload | `ALTER EVENT TRIGGER ... DISABLE` |
| Recomendación | Entornos legacy o con PG < 17 | **Método preferido** para PG 17+ |

---

## 🗂️ Archivos del proyecto

```
pg_session_blocker/
├── block_session_login_hook.sql   # Implementación para PostgreSQL 12 – 16
├── block_session_trigger.sql      # Implementación para PostgreSQL 17+
└── README.md                      # Documentación
```

---

## 🤝 Contribuir

¿Encontraste un bug o tienes una idea? Abre un [Issue](https://github.com/CR0NYM3X/pg_session_blocker/issues) o envía un Pull Request. Toda contribución es bienvenida.

---

## ✒️ Autor

Desarrollado por [**CR0NYM3X**](https://github.com/CR0NYM3X)

---

<p align="center">
  <i>Si este proyecto te fue útil, regálale una ⭐ en GitHub.</i>
</p>
