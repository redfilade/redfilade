-- 0002_bench.sql
-- Hosted Test Bench (Phase 3d, ADR-0022): API keys, verified domains, remote
-- test runs and their evidence.
--
-- Every new table carries org_id with row-level security enabled and forced.
-- Two SECURITY DEFINER functions are the only way across tenants, and each
-- does one narrow thing: find the org of an API key hash, and claim the next
-- queued run for a worker. Run this migration as the database owner (a role
-- with BYPASSRLS or a superuser), so those functions can read past RLS.

BEGIN;

-- ---------------------------------------------------------------- API keys
-- Only a SHA-256 hash of each key is stored; the key is shown once.
CREATE TABLE redfilade.api_keys (
  id          uuid PRIMARY KEY DEFAULT redfilade.uuid_v7(),
  org_id      uuid NOT NULL REFERENCES redfilade.orgs (id) ON DELETE CASCADE,
  name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  prefix      text NOT NULL CHECK (prefix ~ '^rfk_[a-z0-9]{8}$'),
  key_hash    bytea NOT NULL UNIQUE CHECK (length(key_hash) = 32),
  role        text NOT NULL CHECK (role IN ('admin', 'tester', 'viewer')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  revoked_at  timestamptz
);
CREATE INDEX api_keys_org_idx ON redfilade.api_keys (org_id, id);

-- ---------------------------------------------------------------- domains
CREATE TABLE redfilade.domains (
  org_id      uuid NOT NULL REFERENCES redfilade.orgs (id) ON DELETE CASCADE,
  domain      text NOT NULL CHECK (domain ~ '^[a-z0-9][a-z0-9.-]{1,251}[a-z0-9]$'),
  token       text NOT NULL CHECK (token ~ '^redfilade-verify=[a-z2-7]{32}$'),
  method      text CHECK (method IN ('dns', 'https')),
  verified_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, domain)
);

-- ---------------------------------------------------------------- runs
ALTER TABLE redfilade.runs
  ADD COLUMN target_url  text CHECK (target_url IS NULL OR (target_url ~ '^https://' AND length(target_url) <= 2048)),
  ADD COLUMN protocol    text CHECK (protocol IS NULL OR protocol IN ('2026-07-28', '2025-11-25')),
  ADD COLUMN verdict     text CHECK (verdict IS NULL OR verdict IN ('exploited', 'not_exploited', 'inconclusive')),
  ADD COLUMN error       text CHECK (error IS NULL OR length(error) <= 2000),
  ADD COLUMN pinned_addr text,
  ADD COLUMN api_key_id  uuid REFERENCES redfilade.api_keys (id),
  ADD COLUMN started_at  timestamptz;
ALTER TABLE redfilade.runs ADD CONSTRAINT runs_org_id_id_key UNIQUE (org_id, id);
CREATE INDEX runs_queued_idx ON redfilade.runs (id) WHERE status = 'queued';

-- ---------------------------------------------------------------- evidence
-- Write-once: inserted when a run finishes, never changed (ADR-0004).
CREATE TABLE redfilade.run_evidence (
  run_id      uuid PRIMARY KEY,
  org_id      uuid NOT NULL,
  -- Stored as the exact bytes that were hashed, so sha256 always verifies.
  evidence    text NOT NULL CHECK (evidence IS JSON OBJECT AND length(evidence) <= 16777216),
  sha256      bytea NOT NULL CHECK (length(sha256) = 32 AND sha256 = sha256(convert_to(evidence, 'UTF8'))),
  created_at  timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (org_id, run_id) REFERENCES redfilade.runs (org_id, id) ON DELETE CASCADE
);

CREATE FUNCTION redfilade.run_evidence_write_once() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'run_evidence is write-once';
END;
$$;
CREATE TRIGGER run_evidence_no_update_or_delete
  BEFORE UPDATE OR DELETE OR TRUNCATE ON redfilade.run_evidence
  FOR EACH STATEMENT EXECUTE FUNCTION redfilade.run_evidence_write_once();

-- ---------------------------------------------------------------- row-level security
ALTER TABLE redfilade.api_keys     ENABLE ROW LEVEL SECURITY;
ALTER TABLE redfilade.api_keys     FORCE ROW LEVEL SECURITY;
ALTER TABLE redfilade.domains      ENABLE ROW LEVEL SECURITY;
ALTER TABLE redfilade.domains      FORCE ROW LEVEL SECURITY;
ALTER TABLE redfilade.run_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE redfilade.run_evidence FORCE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON redfilade.api_keys
  USING (org_id = redfilade.current_org()) WITH CHECK (org_id = redfilade.current_org());
CREATE POLICY org_isolation ON redfilade.domains
  USING (org_id = redfilade.current_org()) WITH CHECK (org_id = redfilade.current_org());
CREATE POLICY org_isolation ON redfilade.run_evidence
  USING (org_id = redfilade.current_org()) WITH CHECK (org_id = redfilade.current_org());

-- ---------------------------------------------------------------- cross-tenant functions
-- Find the org behind an API key hash (authentication happens before the org
-- is known). Returns nothing for unknown or revoked keys.
CREATE FUNCTION redfilade.authenticate_api_key(h bytea)
RETURNS TABLE (key_id uuid, org_id uuid, role text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, redfilade AS $$
  SELECT k.id, k.org_id, k.role FROM redfilade.api_keys k
  WHERE k.key_hash = h AND k.revoked_at IS NULL
$$;

-- Claim the oldest queued run for a worker (ADR-0005). Concurrent workers
-- never get the same run.
CREATE FUNCTION redfilade.claim_run()
RETURNS TABLE (run_id uuid, org_id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, redfilade AS $$
  UPDATE redfilade.runs r SET status = 'running', started_at = now()
  WHERE r.id = (SELECT id FROM redfilade.runs WHERE status = 'queued' ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1)
  RETURNING r.id, r.org_id
$$;

REVOKE ALL ON FUNCTION redfilade.authenticate_api_key(bytea), redfilade.claim_run() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION redfilade.authenticate_api_key(bytea), redfilade.claim_run() TO redfilade_app;

GRANT SELECT, INSERT, UPDATE ON redfilade.api_keys, redfilade.domains TO redfilade_app;
GRANT SELECT, INSERT ON redfilade.run_evidence TO redfilade_app;

COMMIT;
