-- CritForge M0 initial schema.
-- Core authorization & audit tables. No scan/finding tables yet (M1+).

CREATE TABLE IF NOT EXISTS project (
    id            BIGSERIAL PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    authorized_by TEXT NOT NULL,
    authorization_reference TEXT
);

CREATE TABLE IF NOT EXISTS scope (
    id            BIGSERIAL PRIMARY KEY,
    project_id    BIGINT NOT NULL REFERENCES project(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL CHECK (kind IN ('allow','deny')),
    target        TEXT NOT NULL,
    severity_gate TEXT NOT NULL DEFAULT 'High'
                  CHECK (severity_gate IN ('Info','Low','Medium','High','Critical')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, kind, target)
);

-- Append-only audit log. No UPDATE/DELETE is expected; enforced below.
CREATE TABLE IF NOT EXISTS audit_log (
    id         BIGSERIAL PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    scope      TEXT,
    detail     TEXT
);

CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: % not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_no_mutate ON audit_log;
CREATE TRIGGER audit_log_no_mutate
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
