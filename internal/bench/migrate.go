// Package bench is the hosted Test Bench (Phase 3d, ADR-0022): an HTTP API
// for organisations to verify domains and test their remote MCP servers, a
// Postgres-backed queue, and workers that run the remote-safe battery.
package bench

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/redfilade/redfilade/db"
	"github.com/redfilade/redfilade/internal/pg"
)

// Migrate applies every migration in db/migrations that has not run yet, each
// in its own transaction together with its bookkeeping row.
func Migrate(ctx context.Context, c *pg.Conn) ([]string, error) {
	if err := c.Script(ctx, `CREATE SCHEMA IF NOT EXISTS redfilade;
CREATE TABLE IF NOT EXISTS redfilade.schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return nil, err
	}
	r, err := c.Exec(ctx, "SELECT version FROM redfilade.schema_migrations")
	if err != nil {
		return nil, err
	}
	done := map[string]bool{}
	for _, row := range r.Data {
		done[*row[0]] = true
	}
	names, err := fs.Glob(db.Files, "migrations/*.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var applied []string
	for _, n := range names {
		version := strings.TrimSuffix(path.Base(n), ".sql")
		if done[version] {
			continue
		}
		b, err := fs.ReadFile(db.Files, n)
		if err != nil {
			return applied, err
		}
		sql := string(b)
		i := strings.LastIndex(sql, "COMMIT;")
		if i < 0 || !strings.Contains(sql, "BEGIN;") {
			return applied, fmt.Errorf("%s must be wrapped in BEGIN; ... COMMIT;", n)
		}
		// version comes from our own embedded file name, never from input.
		sql = sql[:i] + "INSERT INTO redfilade.schema_migrations (version) VALUES ('" + version + "');\n" + sql[i:]
		if err := c.Script(ctx, sql); err != nil {
			_ = c.Script(context.Background(), "ROLLBACK")
			return applied, fmt.Errorf("%s: %w", version, err)
		}
		applied = append(applied, version)
	}
	return applied, nil
}

// TenancyTest runs db/tests/tenancy_test.sql. It needs a superuser
// connection and rolls back everything it creates.
func TenancyTest(ctx context.Context, c *pg.Conn) error {
	b, err := fs.ReadFile(db.Files, "tests/tenancy_test.sql")
	if err != nil {
		return err
	}
	return c.Script(ctx, string(b))
}
