package pg_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/redfilade/redfilade/internal/pg"
	"github.com/redfilade/redfilade/internal/pg/pgtest"
)

func TestParseURL(t *testing.T) {
	c, err := pg.ParseURL("postgres://app:pw@127.0.0.1/db")
	if err != nil || c.SSLMode != "disable" || c.Port != "5432" || c.Password != "pw" {
		t.Fatal(c, err)
	}
	c, _ = pg.ParseURL("postgres://app@db.example.com:6543/x")
	if c.SSLMode != "verify-full" {
		t.Fatal("remote hosts must default to verified TLS", c)
	}
	for _, bad := range []string{"mysql://x@y/z", "postgres:///db", "postgres://u@h/d?sslmode=prefer"} {
		if _, err := pg.ParseURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestQueriesAgainstRealPostgres(t *testing.T) {
	dsn := pgtest.URL(t)
	ctx := context.Background()
	c, err := pg.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Script(ctx, "CREATE TABLE t (id int PRIMARY KEY, name text, data bytea, ok bool, at timestamptz, doc jsonb)"); err != nil {
		t.Fatal(err)
	}
	evil := "x'); DROP TABLE t; --"
	now := time.Date(2026, 11, 15, 8, 0, 0, 0, time.UTC)
	r, err := c.Exec(ctx, "INSERT INTO t VALUES ($1, $2, $3, $4, $5, $6)", 1, evil, []byte{0, 1, 255}, true, now, []byte(`{"a":1}`)[:0:0])
	if err == nil {
		t.Fatal("bytea passed as jsonb should fail") // the []byte goes as bytea text, invalid for jsonb
	}
	r, err = c.Exec(ctx, "INSERT INTO t (id, name, data, ok, at) VALUES ($1, $2, $3, $4, $5)", 1, evil, []byte{0, 1, 255}, true, now)
	if err != nil || r.Affected() != 1 {
		t.Fatal(r, err)
	}
	r, err = c.Exec(ctx, "SELECT name, encode(data, 'hex'), ok, at, doc FROM t WHERE id = $1", 1)
	if err != nil || len(r.Data) != 1 {
		t.Fatal(r, err)
	}
	row := r.Data[0]
	if *row[0] != evil || *row[1] != "0001ff" || *row[2] != "t" || row[4] != nil || !strings.HasPrefix(*row[3], "2026-11-15") {
		t.Fatalf("row %q %q %q %v", *row[0], *row[1], *row[2], row[4])
	}
	if r.Columns[0] != "name" {
		t.Fatal(r.Columns)
	}
	// Errors carry the SQLSTATE, and the connection stays usable.
	_, err = c.Exec(ctx, "INSERT INTO t (id) VALUES ($1)", 1)
	var pe *pg.Error
	if !errors.As(err, &pe) || pe.Code != "23505" {
		t.Fatalf("duplicate key: %v", err)
	}
	if _, err := c.Exec(ctx, "SELECT 1"); err != nil {
		t.Fatal("connection unusable after an error:", err)
	}
	if _, err := c.Exec(ctx, "SELECT $1::text", "a\x00b"); err == nil {
		t.Fatal("NUL byte accepted")
	}
}

func TestWrongPasswordIsRefused(t *testing.T) {
	u, _ := url.Parse(pgtest.URL(t))
	pw, ok := u.User.Password()
	if !ok {
		t.Skip("URL has no password")
	}
	u.User = url.UserPassword(u.User.Username(), pw+"-wrong")
	_, err := pg.Connect(context.Background(), u.String())
	var pe *pg.Error
	if !errors.As(err, &pe) || pe.Code != "28P01" {
		t.Fatalf("wrong password: want SQLSTATE 28P01, got %v", err)
	}
}

func TestPoolAndTx(t *testing.T) {
	dsn := pgtest.URL(t)
	ctx := context.Background()
	p := pg.NewPool(dsn, 4)
	defer p.Close()
	if err := p.With(ctx, func(c *pg.Conn) error { return c.Script(ctx, "CREATE TABLE n (v int)") }); err != nil {
		t.Fatal(err)
	}
	_ = p.Tx(ctx, func(c *pg.Conn) error {
		if _, err := c.Exec(ctx, "INSERT INTO n VALUES ($1)", 1); err != nil {
			return err
		}
		return errors.New("roll it back")
	})
	if err := p.Tx(ctx, func(c *pg.Conn) error { _, err := c.Exec(ctx, "INSERT INTO n VALUES ($1)", 2); return err }); err != nil {
		t.Fatal(err)
	}
	var got string
	_ = p.With(ctx, func(c *pg.Conn) error {
		r, err := c.Exec(ctx, "SELECT string_agg(v::text, ',') FROM n")
		if err == nil {
			got = *r.Data[0][0]
		}
		return err
	})
	if got != "2" {
		t.Fatalf("rows after rollback and commit: %q", got)
	}
	ctx2, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	err := p.With(ctx2, func(c *pg.Conn) error { _, err := c.Exec(ctx2, "SELECT pg_sleep(2)"); return err })
	if err == nil {
		t.Fatal("a cancelled query should fail")
	}
}

// TestPoolSurvivesCancelledContexts reproduces requests whose context ends
// right after their query: no pooled connection may be left broken.
func TestPoolSurvivesCancelledContexts(t *testing.T) {
	p := pg.NewPool(pgtest.URL(t), 2)
	defer p.Close()
	for i := 0; i < 300; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		err := p.With(ctx, func(c *pg.Conn) error { _, err := c.Exec(ctx, "SELECT 1"); return err })
		cancel()
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}
}
