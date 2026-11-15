// Command redfilade-bench runs the hosted Test Bench (ADR-0022).
//
//	redfilade-bench migrate                       apply database migrations (owner role)
//	redfilade-bench create-org --slug S --name N  create an organisation and print its admin key
//	redfilade-bench serve [--addr A] [--workers N] [--tls-cert F --tls-key F]
//
// Database URLs come from the environment, never from flags:
// REDFILADE_BENCH_MIGRATE_URL for migrate (a role that owns the schema), and
// REDFILADE_BENCH_DATABASE_URL for everything else (a login role in
// redfilade_app, without BYPASSRLS).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redfilade/redfilade/internal/bench"
	"github.com/redfilade/redfilade/internal/domain"
	"github.com/redfilade/redfilade/internal/pg"
	"github.com/redfilade/redfilade/internal/version"
)

func main() { os.Exit(run(os.Args[1:])) }

func usage() int {
	fmt.Fprintln(os.Stderr, "usage: redfilade-bench migrate | create-org --slug S --name N | serve [--addr A] [--workers N] [--tls-cert F --tls-key F]")
	return 2
}

func dbURL(name string) (string, error) {
	u := os.Getenv(name)
	if u == "" {
		return "", fmt.Errorf("%s is not set", name)
	}
	return u, nil
}

func run(args []string) int {
	if len(args) == 0 {
		return usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	switch args[0] {
	case "migrate":
		u, err := dbURL("REDFILADE_BENCH_MIGRATE_URL")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		c, err := pg.Connect(ctx, u)
		if err != nil {
			fmt.Fprintln(os.Stderr, "connect:", err)
			return 1
		}
		defer c.Close()
		applied, err := bench.Migrate(ctx, c)
		if err != nil {
			fmt.Fprintln(os.Stderr, "migrate:", err)
			return 1
		}
		fmt.Printf("applied %d migration(s): %v\n", len(applied), applied)
		return 0
	case "create-org":
		fs := flag.NewFlagSet("create-org", flag.ContinueOnError)
		slug := fs.String("slug", "", "short name: lowercase letters, digits and dashes")
		name := fs.String("name", "", "display name")
		if fs.Parse(args[1:]) != nil || *slug == "" || *name == "" {
			return usage()
		}
		u, err := dbURL("REDFILADE_BENCH_DATABASE_URL")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		p := pg.NewPool(u, 1)
		defer p.Close()
		org, key, err := bench.NewStore(p).CreateOrg(ctx, *slug, *name)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create-org:", err)
			return 1
		}
		fmt.Printf("organisation %s (%s)\nadmin API key (shown once, store it now): %s\n", *slug, org, key)
		return 0
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		addr := fs.String("addr", "127.0.0.1:8090", "listen address")
		workers := fs.Int("workers", 2, "concurrent remote test runs")
		cert := fs.String("tls-cert", "", "TLS certificate file (required unless listening on loopback)")
		key := fs.String("tls-key", "", "TLS key file")
		if fs.Parse(args[1:]) != nil || *workers < 1 || *workers > 32 {
			return usage()
		}
		host, _, err := net.SplitHostPort(*addr)
		if err != nil {
			return usage()
		}
		if ip := net.ParseIP(host); (*cert == "" || *key == "") && (ip == nil || !ip.IsLoopback()) {
			fmt.Fprintln(os.Stderr, "redfilade-bench: refusing to serve API keys over plain HTTP on a non-loopback address; pass --tls-cert and --tls-key")
			return 2
		}
		u, err := dbURL("REDFILADE_BENCH_DATABASE_URL")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		v, err := domain.NewVerifier()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		pool := pg.NewPool(u, 8+*workers)
		defer pool.Close()
		svc := &bench.Service{Store: bench.NewStore(pool), Verifier: v, Version: version.Version, Log: log}
		srv := &http.Server{Addr: *addr, Handler: svc.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
		go svc.Work(ctx, *workers)
		go func() {
			<-ctx.Done()
			sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = srv.Shutdown(sctx)
		}()
		log.Info("serving", "addr", *addr, "workers", *workers, "tls", *cert != "")
		if *cert != "" {
			err = srv.ListenAndServeTLS(*cert, *key)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("serve", "error", err.Error())
			return 1
		}
		return 0
	}
	return usage()
}
