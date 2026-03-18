-- ============================================================================
-- pg-login-guard: Maintenance & Monitoring Queries
-- ============================================================================


-- ┌─────────────────────────────────────────────────────────────────┐
-- │  MANAGING BLOCKED APPLICATIONS                                 │
-- └─────────────────────────────────────────────────────────────────┘

-- Add a new blocked application
INSERT INTO sec_dba.blocked_applications (app_pattern, description)
VALUES ('%pgAdmin%', 'pgAdmin blocked in production');

-- Temporarily disable a rule (without deleting it)
UPDATE sec_dba.blocked_applications
SET    is_active = FALSE
WHERE  app_pattern = '%pgAdmin%';

-- Re-enable
UPDATE sec_dba.blocked_applications
SET    is_active = TRUE
WHERE  app_pattern = '%pgAdmin%';

-- List all rules and their status
SELECT id, app_pattern, description, is_active, created_at, created_by
FROM   sec_dba.blocked_applications
ORDER  BY id;


-- ┌─────────────────────────────────────────────────────────────────┐
-- │  MANAGING EXEMPT USERS                                         │
-- └─────────────────────────────────────────────────────────────────┘

-- Exempt a specific DBA user
INSERT INTO sec_dba.exempt_users (username_pattern, description)
VALUES ('^dba_admin$', 'DBA admin account — full access');

-- Exempt all users with a role prefix
INSERT INTO sec_dba.exempt_users (username_pattern, description)
VALUES ('^svc_', 'Service accounts are exempt');

-- List all exemptions
SELECT id, username_pattern, description, is_active, created_at
FROM   sec_dba.exempt_users
ORDER  BY id;


-- ┌─────────────────────────────────────────────────────────────────┐
-- │  AUDIT LOG QUERIES                                             │
-- └─────────────────────────────────────────────────────────────────┘

-- Blocked connections in the last 24 hours
SELECT event_time, session_user_, client_ip, application_name, database_name, message
FROM   sec_dba.login_audit_log
WHERE  event_type = 'BLOCKED'
  AND  event_time >= now() - interval '24 hours'
ORDER  BY event_time DESC;

-- Daily connection summary (last 7 days)
SELECT event_time::date AS day,
       event_type,
       COUNT(*)         AS connections
FROM   sec_dba.login_audit_log
WHERE  event_time >= now() - interval '7 days'
GROUP  BY 1, 2
ORDER  BY 1 DESC, 2;

-- Top blocked users
SELECT session_user_,
       application_name,
       COUNT(*)          AS attempts,
       MAX(event_time)   AS last_attempt
FROM   sec_dba.login_audit_log
WHERE  event_type = 'BLOCKED'
GROUP  BY 1, 2
ORDER  BY attempts DESC
LIMIT  20;

-- Unique applications connecting to the cluster
SELECT DISTINCT application_name,
       COUNT(*)         AS connections,
       MIN(event_time)  AS first_seen,
       MAX(event_time)  AS last_seen
FROM   sec_dba.login_audit_log
WHERE  event_type = 'ALLOWED'
GROUP  BY 1
ORDER  BY connections DESC;

-- Connections per database
SELECT database_name,
       event_type,
       COUNT(*) AS total
FROM   sec_dba.login_audit_log
WHERE  event_time >= now() - interval '30 days'
GROUP  BY 1, 2
ORDER  BY 1, 2;


-- ┌─────────────────────────────────────────────────────────────────┐
-- │  MAINTENANCE                                                   │
-- └─────────────────────────────────────────────────────────────────┘

-- Purge audit records older than 90 days
DELETE FROM sec_dba.login_audit_log
WHERE  event_time < now() - interval '90 days';

-- Estimate table size
SELECT pg_size_pretty(pg_total_relation_size('sec_dba.login_audit_log')) AS audit_log_size;

-- Optional: Convert to partitioned table for high-traffic clusters
-- (requires PostgreSQL 12+, run during maintenance window)
--
-- CREATE TABLE sec_dba.login_audit_log_partitioned (
--     LIKE sec_dba.login_audit_log INCLUDING ALL
-- ) PARTITION BY RANGE (event_time);
--
-- CREATE TABLE sec_dba.login_audit_log_y2025m01
--     PARTITION OF sec_dba.login_audit_log_partitioned
--     FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
