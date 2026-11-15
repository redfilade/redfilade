// Package pgtest gives tests a fresh PostgreSQL database.
//
// It uses REDFILADE_TEST_PG_URL when set (a fresh database is created on that
// server for every call). Otherwise, when initdb is installed and the tests
// do not run as root, it starts a throwaway cluster with SCRAM authentication
// and a random password. Otherwise the test is skipped.
package pgtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/redfilade/redfilade/internal/pg"
)

var (
	once    sync.Once
	baseURL string
	skipWhy string
)

// URL returns a connection URL for a new, empty database.
func URL(t *testing.T) string {
	t.Helper()
	once.Do(func() { baseURL, skipWhy = start() })
	if baseURL == "" {
		if os.Getenv("REDFILADE_REQUIRE_PG") != "" {
			t.Fatalf("PostgreSQL is required here but unavailable: %s", skipWhy)
		}
		t.Skip(skipWhy)
	}
	name := "t_" + randHex(6)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := pg.Connect(ctx, baseURL)
	if err != nil {
		t.Fatalf("pgtest: %v", err)
	}
	defer c.Close()
	if err := c.Script(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("pgtest: %v", err)
	}
	u, _ := url.Parse(baseURL)
	u.Path = "/" + name
	return u.String()
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func start() (string, string) {
	if u := os.Getenv("REDFILADE_TEST_PG_URL"); u != "" {
		return u, ""
	}
	if os.Geteuid() == 0 {
		return "", "set REDFILADE_TEST_PG_URL to run database tests as root"
	}
	bin := ""
	if p, err := exec.LookPath("initdb"); err == nil {
		bin = filepath.Dir(p)
	} else if m, _ := filepath.Glob("/usr/lib/postgresql/*/bin/initdb"); len(m) > 0 {
		bin = filepath.Dir(m[len(m)-1])
	}
	if bin == "" {
		return "", "PostgreSQL is not installed; set REDFILADE_TEST_PG_URL to run database tests"
	}
	dir, err := os.MkdirTemp("", "redfilade-pg-")
	if err != nil {
		return "", err.Error()
	}
	pw := randHex(16)
	pwFile := filepath.Join(dir, "pw")
	if err := os.WriteFile(pwFile, []byte(pw), 0o600); err != nil {
		return "", err.Error()
	}
	data := filepath.Join(dir, "data")
	if out, err := exec.Command(filepath.Join(bin, "initdb"), "-D", data, "-U", "postgres", "--auth=scram-sha-256", "--pwfile="+pwFile).CombinedOutput(); err != nil {
		return "", "initdb: " + err.Error() + ": " + string(out)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err.Error()
	}
	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	opts := "-p " + port + " -k " + dir + " -c listen_addresses=127.0.0.1"
	if out, err := exec.Command(filepath.Join(bin, "pg_ctl"), "-D", data, "-o", opts, "-l", filepath.Join(dir, "log"), "-w", "start").CombinedOutput(); err != nil {
		return "", "pg_ctl: " + err.Error() + ": " + string(out)
	}
	// The cluster stops when the test binary exits only if asked; tests are
	// short-lived, so a leftover temporary cluster is cleaned by the OS.
	return "postgres://postgres:" + pw + "@127.0.0.1:" + port + "/postgres?sslmode=disable", ""
}
