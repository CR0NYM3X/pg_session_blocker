
### 11 - pg_notify
Una propuesta adicional que no está en tu lista pero que yo agregaría: notificaciones vía pg_notify. Cuando una regla DENY se dispara, además de loguear, lanzar un PERFORM pg_notify('security_alert', json_build_object(...)). Esto permite que cualquier aplicación externa (un bot de Slack, un script de monitoreo, Grafana) escuche alertas en tiempo real sin polling. Es una línea de código y abre un mundo de integraciones.

---

# La mejor estrategia para impedir que se conecten con un analizador de consultas como pg_admin es bloquearles el pg_databases al usuario ya que los analizdores de consultas es lo primero revisan y si no pueden consultar les marcara miles de errores


# Ver si es mejor poner una columna mejor donde especificas la IP donde estara solo permitido 


---

Tienes razón, tu tabla usa `NOT NULL` con defaults en todas las columnas.

```sql
ALTER TABLE pg_hba 
  ADD COLUMN apply_on      TEXT NOT NULL DEFAULT 'all' 
      CHECK (apply_on IN ('all', 'primary', 'replica')),
  ADD COLUMN target_server  INET NOT NULL DEFAULT '0.0.0.0';
```

Y la condición en la función:

```sql
  AND (
      apply_on = 'all'
      OR (apply_on = 'primary' AND NOT pg_is_in_recovery())
      OR (apply_on = 'replica'  AND pg_is_in_recovery())
  )
  AND (target_server = '0.0.0.0' OR target_server = inet_server_addr())
```

`0.0.0.0` como default sigue la misma lógica que tu `client_ip` con `0.0.0.0/0` — significa "cualquier servidor".
