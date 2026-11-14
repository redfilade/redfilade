-- 0001_tenancy.sql
-- Multi-tenant foundation (docs/phase-0.md, ADR-004).
--
-- Rules this migration enforces from day one:
--   * Every tenant-owned row carries org_id; project-scoped rows also carry project_id.
--   * A row can never point at a project in a different org (composite foreign keys).
--   * Row-level security is enabled AND forced on every tenant table, so even the
--     table owner is filtered. The application connects as redfilade_app, which
--     has no BYPASSRLS and sees only the org set in `redfilade.org_id` for the
--     current transaction.
--   * IDs are UUIDv7 (time-ordered, index-friendly, not guessable as sequences).
--   * The audit log is append-only.

BEGIN;

CREATE SCHEMA IF NOT EXISTS redfilade;

-- UUIDv7 per RFC 9562: 48-bit Unix milliseconds, version 7, variant 10, random rest.
-- Postgres 18 ships uuidv7(); this function keeps 16 and 17 supported.
CREATE OR REPLACE FUNCTION redfilade.uuid_v7() RETURNS uuid
LANGUAGE plpgsql VOLATILE PARALLEL SAFE AS $$
DECLARE
  ts_ms bigint := floor(extract(epoch FROM clock_timestamp()) * 1000);
  b bytea := decode(lpad(to_hex(ts_ms), 12, '0'), 'hex') || substring(uuid_send(gen_random_uuid()) FROM 7 FOR 10);
BEGIN
  b := set_byte(b, 6, (get_byte(b, 6) & 15) | 112);  -- version 7
  b := set_byte(b, 8, (get_byte(b, 8) & 63) | 128);  -- RFC 9562 variant
  RETURN encode(b, 'hex')::uuid;
END;
$$;

-- The org the current transaction acts for. NULL (no access) when unset.
CREATE OR REPLACE FUNCTION redfilade.current_org() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT nullif(current_setting('redfilade.org_id', true), '')::uuid
$$;

-- ---------------------------------------------------------------- tenants
CREATE TABLE redfilade.orgs (
  id          uuid PRIMARY KEY DEFAULT redfilade.uuid_v7(),
  slug        text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE redfilade.users (
  id          uuid PRIMARY KEY DEFAULT redfilade.uuid_v7(),
  -- Identity comes from GitHub OAuth or enterprise SSO (ADR-009); no passwords stored.
  idp         text NOT NULL CHECK (idp IN ('github', 'oidc', 'saml')),
  idp_subject text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (idp, idp_subject)
);

CREATE TABLE redfilade.memberships (
  org_id      uuid NOT NULL REFERENCES redfilade.orgs (id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES redfilade.users (id) ON DELETE CASCADE,
  role        text NOT NULL CHECK (role IN ('owner', 'admin', 'tester', 'viewer')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, user_id)
);

CREATE TABLE redfilade.projects (
  id          uuid NOT NULL DEFAULT redfilade.uuid_v7(),
  org_id      uuid NOT NULL REFERENCES redfilade.orgs (id) ON DELETE CASCADE,
  slug        text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id),
  UNIQUE (org_id, id),
  UNIQUE (org_id, slug)
);

-- ---------------------------------------------------------------- runs
CREATE TABLE redfilade.runs (
  id          uuid NOT NULL DEFAULT redfilade.uuid_v7() PRIMARY KEY,
  org_id      uuid NOT NULL,
  project_id  uuid NOT NULL,
  level       text NOT NULL CHECK (level IN ('L1', 'L2', 'L3', 'L4', 'L5')),
  status      text NOT NULL DEFAULT 'queued'
              CHECK (status IN ('queued', 'running', 'passed', 'failed', 'error', 'cancelled')),
  requested_by uuid REFERENCES redfilade.users (id),
  created_at  timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  -- The project must belong to the same org as the run.
  FOREIGN KEY (org_id, project_id) REFERENCES redfilade.projects (org_id, id) ON DELETE CASCADE
);
CREATE INDEX runs_org_project_idx ON redfilade.runs (org_id, project_id, id);

-- ---------------------------------------------------------------- audit log
CREATE TABLE redfilade.audit_log (
  id          uuid NOT NULL DEFAULT redfilade.uuid_v7() PRIMARY KEY,
  org_id      uuid NOT NULL REFERENCES redfilade.orgs (id),
  actor_id    uuid REFERENCES redfilade.users (id),
  action      text NOT NULL,
  target      text,
  detail      jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_org_idx ON redfilade.audit_log (org_id, id);

CREATE FUNCTION redfilade.audit_log_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$;
CREATE TRIGGER audit_log_no_update_or_delete
  BEFORE UPDATE OR DELETE OR TRUNCATE ON redfilade.audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION redfilade.audit_log_append_only();

-- ---------------------------------------------------------------- row-level security
ALTER TABLE redfilade.orgs        ENABLE ROW LEVEL SECURITY;
ALTER TABLE redfilade.orgs        FORCE ROW LEVEL SECURITY;
ALTER TABLE redfilade.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE redfilade.memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE redfilade.projects    ENABLE ROW LEVEL SECURITY;
ALTER TABLE redfilade.projects    FORCE ROW LEVEL SECURITY;
ALTER TABLE redfilade.runs        ENABLE ROW LEVEL SECURITY;
ALTER TABLE redfilade.runs        FORCE ROW LEVEL SECURITY;
ALTER TABLE redfilade.audit_log   ENABLE ROW LEVEL SECURITY;
ALTER TABLE redfilade.audit_log   FORCE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON redfilade.orgs
  USING (id = redfilade.current_org()) WITH CHECK (id = redfilade.current_org());
CREATE POLICY org_isolation ON redfilade.memberships
  USING (org_id = redfilade.current_org()) WITH CHECK (org_id = redfilade.current_org());
CREATE POLICY org_isolation ON redfilade.projects
  USING (org_id = redfilade.current_org()) WITH CHECK (org_id = redfilade.current_org());
CREATE POLICY org_isolation ON redfilade.runs
  USING (org_id = redfilade.current_org()) WITH CHECK (org_id = redfilade.current_org());
CREATE POLICY org_isolation ON redfilade.audit_log
  USING (org_id = redfilade.current_org()) WITH CHECK (org_id = redfilade.current_org());

-- ---------------------------------------------------------------- application role
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'redfilade_app') THEN
    CREATE ROLE redfilade_app NOLOGIN NOBYPASSRLS;
  END IF;
END;
$$;

GRANT USAGE ON SCHEMA redfilade TO redfilade_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON
  redfilade.orgs, redfilade.memberships, redfilade.projects, redfilade.runs TO redfilade_app;
GRANT SELECT, INSERT ON redfilade.users TO redfilade_app;
GRANT SELECT, INSERT ON redfilade.audit_log TO redfilade_app;
GRANT EXECUTE ON FUNCTION redfilade.uuid_v7(), redfilade.current_org() TO redfilade_app;

COMMIT;
