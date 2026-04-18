
### 11 - pg_notify
Una propuesta adicional que no está en tu lista pero que yo agregaría: notificaciones vía pg_notify. Cuando una regla DENY se dispara, además de loguear, lanzar un PERFORM pg_notify('security_alert', json_build_object(...)). Esto permite que cualquier aplicación externa (un bot de Slack, un script de monitoreo, Grafana) escuche alertas en tiempo real sin polling. Es una línea de código y abre un mundo de integraciones.

---

# La mejor estrategia para impedir que se conecten con un analizador de consultas como pg_admin es bloquearles el pg_databases al usuario ya que los analizdores de consultas es lo primero revisan y si no pueden consultar les marcara miles de errores

