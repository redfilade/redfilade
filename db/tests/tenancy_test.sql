-- Tenant-isolation test for 0001_tenancy.sql and 0002_bench.sql. Run after the migration, as a
-- superuser, against a throwaway database. Any failed check raises an error.

BEGIN;

-- Seed two orgs as the table owner, each inside its own org context.
SELECT set_config('redfilade.org_id', '01900000-0000-7000-8000-00000000000a', true);
INSERT INTO redfilade.orgs (id, slug, name) VALUES ('01900000-0000-7000-8000-00000000000a', 'acme', 'Acme');
INSERT INTO redfilade.projects (id, org_id, slug, name)
  VALUES ('01900000-0000-7000-8000-0000000000a1', '01900000-0000-7000-8000-00000000000a', 'gateway', 'Gateway');
INSERT INTO redfilade.runs (org_id, project_id, level)
  VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-0000000000a1', 'L1');

SELECT set_config('redfilade.org_id', '01900000-0000-7000-8000-00000000000b', true);
INSERT INTO redfilade.orgs (id, slug, name) VALUES ('01900000-0000-7000-8000-00000000000b', 'globex', 'Globex');
INSERT INTO redfilade.projects (id, org_id, slug, name)
  VALUES ('01900000-0000-7000-8000-0000000000b1', '01900000-0000-7000-8000-00000000000b', 'tools', 'Tools');
INSERT INTO redfilade.api_keys (org_id, name, prefix, key_hash, role)
  VALUES ('01900000-0000-7000-8000-00000000000b', 'ci', 'rfk_globex01', sha256('globex-key'), 'tester');
INSERT INTO redfilade.domains (org_id, domain, token)
  VALUES ('01900000-0000-7000-8000-00000000000b', 'globex.example', 'redfilade-verify=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
INSERT INTO redfilade.runs (id, org_id, project_id, level, status)
  VALUES ('01900000-0000-7000-8000-0000000000b9', '01900000-0000-7000-8000-00000000000b', '01900000-0000-7000-8000-0000000000b1', 'L2', 'passed');
INSERT INTO redfilade.run_evidence (run_id, org_id, evidence, sha256)
  VALUES ('01900000-0000-7000-8000-0000000000b9', '01900000-0000-7000-8000-00000000000b', '{}', sha256(convert_to('{}', 'UTF8')));

SET LOCAL ROLE redfilade_app;

DO $$
DECLARE n int;
BEGIN
  -- 1. With no org set, nothing is visible.
  PERFORM set_config('redfilade.org_id', '', true);
  SELECT count(*) INTO n FROM redfilade.projects;
  IF n <> 0 THEN RAISE EXCEPTION 'FAIL 1: % projects visible with no org set', n; END IF;

  -- 2. Acme sees exactly its own project and run.
  PERFORM set_config('redfilade.org_id', '01900000-0000-7000-8000-00000000000a', true);
  SELECT count(*) INTO n FROM redfilade.projects;
  IF n <> 1 THEN RAISE EXCEPTION 'FAIL 2: acme sees % projects', n; END IF;
  SELECT count(*) INTO n FROM redfilade.runs;
  IF n <> 1 THEN RAISE EXCEPTION 'FAIL 2b: acme sees % runs', n; END IF;

  -- 3. Acme cannot read Globex's project by id.
  SELECT count(*) INTO n FROM redfilade.projects WHERE id = '01900000-0000-7000-8000-0000000000b1';
  IF n <> 0 THEN RAISE EXCEPTION 'FAIL 3: cross-tenant read'; END IF;

  -- 4. Acme cannot write a row into Globex.
  BEGIN
    INSERT INTO redfilade.projects (org_id, slug, name)
      VALUES ('01900000-0000-7000-8000-00000000000b', 'evil', 'Evil');
    RAISE EXCEPTION 'FAIL 4: cross-tenant insert succeeded';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  -- 5. Acme cannot update Globex's rows (they are invisible, so 0 rows change).
  UPDATE redfilade.projects SET name = 'pwned' WHERE id = '01900000-0000-7000-8000-0000000000b1';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN RAISE EXCEPTION 'FAIL 5: cross-tenant update changed % rows', n; END IF;

  -- 6. A run cannot point at another org's project, even if the org_id is its own.
  BEGIN
    INSERT INTO redfilade.runs (org_id, project_id, level)
      VALUES ('01900000-0000-7000-8000-00000000000a', '01900000-0000-7000-8000-0000000000b1', 'L1');
    RAISE EXCEPTION 'FAIL 6: run linked to a foreign project';
  EXCEPTION WHEN foreign_key_violation THEN NULL;
  END;

  -- 7. The audit log accepts inserts and refuses updates and deletes.
  INSERT INTO redfilade.audit_log (org_id, action) VALUES ('01900000-0000-7000-8000-00000000000a', 'test.insert');
  BEGIN
    DELETE FROM redfilade.audit_log;
    RAISE EXCEPTION 'FAIL 7: audit log row deleted';
  EXCEPTION WHEN insufficient_privilege OR raise_exception THEN
    IF SQLERRM LIKE 'FAIL%' THEN RAISE; END IF;
  END;

  -- 8. Generated IDs are version-7 UUIDs and sort by creation time.
  IF substring(redfilade.uuid_v7()::text FROM 15 FOR 1) <> '7' THEN RAISE EXCEPTION 'FAIL 8: not UUIDv7'; END IF;
  IF substring(redfilade.uuid_v7()::text FROM 20 FOR 1) NOT IN ('8', '9', 'a', 'b') THEN RAISE EXCEPTION 'FAIL 8b: bad variant'; END IF;

  -- 9. Bench tables: Acme sees none of Globex's keys, domains or evidence.
  PERFORM set_config('redfilade.org_id', '01900000-0000-7000-8000-00000000000a', true);
  SELECT count(*) INTO n FROM redfilade.api_keys;
  IF n <> 0 THEN RAISE EXCEPTION 'FAIL 9: acme sees % api keys', n; END IF;
  SELECT count(*) INTO n FROM redfilade.domains;
  IF n <> 0 THEN RAISE EXCEPTION 'FAIL 9b: acme sees % domains', n; END IF;
  SELECT count(*) INTO n FROM redfilade.run_evidence;
  IF n <> 0 THEN RAISE EXCEPTION 'FAIL 9c: acme sees % evidence rows', n; END IF;

  -- 10. Acme cannot plant a domain or key in Globex.
  BEGIN
    INSERT INTO redfilade.domains (org_id, domain, token)
      VALUES ('01900000-0000-7000-8000-00000000000b', 'evil.example', 'redfilade-verify=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
    RAISE EXCEPTION 'FAIL 10: cross-tenant domain insert succeeded';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  -- 11. Evidence cannot point at another org's run, and is write-once.
  BEGIN
    INSERT INTO redfilade.run_evidence (run_id, org_id, evidence, sha256)
      VALUES ('01900000-0000-7000-8000-0000000000b9', '01900000-0000-7000-8000-00000000000a', '{}', sha256(convert_to('{}', 'UTF8')));
    RAISE EXCEPTION 'FAIL 11: evidence linked to a foreign run';
  EXCEPTION WHEN foreign_key_violation OR unique_violation THEN NULL;
  END;
  PERFORM set_config('redfilade.org_id', '01900000-0000-7000-8000-00000000000b', true);
  BEGIN
    UPDATE redfilade.run_evidence SET evidence = '{"tampered":true}', sha256 = sha256(convert_to('{"tampered":true}', 'UTF8'));
    RAISE EXCEPTION 'FAIL 11b: evidence updated';
  EXCEPTION WHEN raise_exception OR insufficient_privilege THEN
    IF SQLERRM LIKE 'FAIL%' THEN RAISE; END IF;
  END;

  -- 12. Key lookup works without an org, finds only live keys, and returns the right org.
  PERFORM set_config('redfilade.org_id', '', true);
  SELECT count(*) INTO n FROM redfilade.authenticate_api_key(sha256('globex-key'))
    WHERE org_id = '01900000-0000-7000-8000-00000000000b';
  IF n <> 1 THEN RAISE EXCEPTION 'FAIL 12: key lookup found % rows', n; END IF;
  SELECT count(*) INTO n FROM redfilade.authenticate_api_key(sha256('no-such-key'));
  IF n <> 0 THEN RAISE EXCEPTION 'FAIL 12b: unknown key found'; END IF;

  RAISE NOTICE 'tenancy_test: all checks passed';
END;
$$;

ROLLBACK;
