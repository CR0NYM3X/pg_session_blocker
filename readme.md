

# pg\_session\_blocker 🛡️

 
`pg_session_blocker` es una solución técnica para el control de acceso dinámico en PostgreSQL, diseñada para cumplir con estándares de seguridad como **NIST SP 800-53** e **ISO 27001**.

Permite gestionar el bloqueo de conexiones de forma granular (por IP, Usuario y Aplicación) sin necesidad de modificar el archivo físico `pg_hba.conf` ni reiniciar el servicio, lo cual es crítico en entornos de **Cloud SQL**, **VMs** y arquitecturas con **Réplicas de Lectura**.

-----

## 🧠 Arquitectura y Lógica de Cumplimiento

El proyecto resuelve la rigidez de las reglas de red tradicionales mediante una capa de validación lógica dentro del motor de la base de datos.

### Casos de Uso Críticos:

1.  **Aislamiento de Carga en Réplicas:** Previene que herramientas de extracción de datos (ej. `pg_dump`) saturen el nodo **Primario**, forzando su ejecución únicamente en nodos de **Réplica**.
2.  **Control de Aplicaciones no Autorizadas:** Bloquea el acceso desde clientes como `pgAdmin` o `DBeaver` para usuarios específicos, obligándolos a usar el stack de aplicaciones corporativo.
3.  **Seguridad Dinámica en Cloud:** Permite habilitar o deshabilitar rangos de IP (`CIDR`) en tiempo real mediante una simple sentencia SQL, ideal para entornos donde la propagación de reglas de firewall de red es lenta.

-----

## 📊 Estructura de Control (`public.pg_hba`)

La lógica se apoya en una tabla centralizada que emula el comportamiento del archivo de configuración nativo de PostgreSQL, pero con capacidades extendidas:

| Columna | Tipo | Función |
| :--- | :--- | :--- |
| `client_ip` | **CIDR** | Rango de red o IP específica (ej. `10.0.0.1/32`). |
| `username_regex` | **TEXT** | Expresión regular para filtrar uno o múltiples usuarios. |
| `app_name_regex` | **TEXT** | Filtro por nombre de aplicación (ej. `^pg_dump$`). |
| `rule_type` | **TEXT** | Define si la regla es de permitir (`ALLOW`) o denegar (`DENY`). |
| `is_blocking` | **BOOL** | `true` aborta la sesión; `false` solo emite un aviso (Notice). |
| `error_msg` | **TEXT** | Mensaje personalizado que recibirá el cliente al ser bloqueado. |

-----

## 🛠️ Implementación por Versión

Dependiendo de tu versión de PostgreSQL, debes aplicar el script correspondiente para activar la intercepción:

### v12 a v16: `block_session_login_hook.sql`

Implementa un **Hook de Post-Autenticación**. Intercepta la conexión inmediatamente después de que el usuario se identifica, pero antes de otorgar acceso al catálogo.

### v17 en adelante: `block_session_trigger.sql`

Utiliza el nuevo **Event Trigger de Login** nativo. Es la forma más moderna y eficiente de gestionar políticas de acceso procedimentales en PostgreSQL 17+.

-----

## 🚀 Ejemplos de Configuración y Laboratorio

### 1\. Bloqueo de herramientas de Backup en el Nodo Principal

Evita que se ejecuten volcados de datos que afecten el rendimiento de producción.

```sql
INSERT INTO public.pg_hba (username_regex, app_name_regex, rule_type, error_msg)
VALUES ('ALL', 'pg_dump', 'DENY', 'ACCESO DENEGADO: Realice sus backups en la REPLICA (Puerto 5433)');
```

### 2\. Restricción de Segmento IP para Usuarios Específicos

Ideal para cumplir con el control de acceso basado en ubicación (NIST).

```sql
INSERT INTO public.pg_hba (client_ip, username_regex, rule_type, error_msg)
VALUES ('192.168.1.0/24', 'root_admin', 'DENY', 'ALERTA: Acceso de admin prohibido desde red pública.');
```

### 3\. Modo de Auditoría (No Bloqueante)

Si deseas monitorear sin desconectar al usuario, cambia `is_blocking` a `false`.

```sql
INSERT INTO public.pg_hba (username_regex, is_blocking, error_msg)
VALUES ('usuario_test', false, 'AVISO: Su actividad está siendo monitoreada por auditoría.');
```

-----

## 📂 Estructura de Directorios

```bash
.
├── block_session_login_hook.sql   # Implementación para PG 12-16.
├── block_session_trigger.sql      # Implementación para PG 17+.
├── DDL_table_setup.sql            # Creación de la tabla public.pg_hba.
└── README.md                      # Esta guía.
```

-----

## ✒️ Autor

  * **Desarrollo y Estrategia:** [CR0NYM3X](https://www.google.com/search?q=https://github.com/CR0NYM3X)
  * **Enfoque:** Seguridad Defensiva y Cumplimiento Normativo (Compliance-as-Code).
