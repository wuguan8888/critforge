DROP TRIGGER IF EXISTS audit_log_no_mutate ON audit_log;
DROP FUNCTION IF EXISTS audit_log_immutable();
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS scope;
DROP TABLE IF EXISTS project;
