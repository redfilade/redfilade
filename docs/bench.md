# Running the hosted Test Bench

The Test Bench (`redfilade-bench`) lets organisations verify their domains and test their remote MCP servers over HTTPS. Design: [ADR-0022](adr/0022-hosted-test-bench-mvp.md).

## Set up

You need PostgreSQL 16 or newer.

```sh
go build -o redfilade-bench ./cmd/redfilade-bench

# 1. Apply migrations as the schema owner (a superuser or a role with BYPASSRLS).
export REDFILADE_BENCH_MIGRATE_URL='postgres://owner:...@db.example.com/redfilade'
./redfilade-bench migrate

# 2. Create a login role for the service, in redfilade_app, without BYPASSRLS (as the owner):
#    CREATE ROLE bench LOGIN PASSWORD '...' IN ROLE redfilade_app;

# 3. Run the service with that role.
export REDFILADE_BENCH_DATABASE_URL='postgres://bench:...@db.example.com/redfilade'
./redfilade-bench create-org --slug acme --name "Acme"      # prints the admin API key once
./redfilade-bench serve --addr 0.0.0.0:8443 --tls-cert cert.pem --tls-key key.pem --workers 2
```

Database URLs come only from the environment. Off loopback, connections use TLS with certificate verification by default (`sslmode=verify-full`).

## API

All endpoints need `Authorization: Bearer rfk_…`. Roles: `viewer` can read, `tester` can also verify domains and start runs, `admin` can also create keys.

| Method and path | Does |
|---|---|
| `POST /v1/domains` `{"domain": "example.com"}` | Create a challenge; returns the token, the DNS TXT name and the HTTPS URL to publish it at |
| `POST /v1/domains/{domain}/verify` | Check the published proof |
| `GET /v1/domains` | List the org's domains |
| `POST /v1/runs` `{"url": "https://api.example.com/mcp", "level": "L2", "target_token": "…"}` | Queue a remote test (202) |
| `GET /v1/runs`, `GET /v1/runs/{id}` | Status: queued, running, passed, failed or error |
| `GET /v1/runs/{id}/evidence` | The run's evidence JSON |
| `POST /v1/keys` `{"name": "ci", "role": "tester"}` | Create another key (admin) |

## Safety rules the service enforces

- Only `https` URLs on domains the org has verified; never IP addresses or localhost.
- The worker checks the proof again and resolves the host at run time; any non-public address (private, loopback, link-local or cloud metadata, CGNAT) stops the run. The connection is pinned to one public address.
- Only remote-safe L1 and L2 attacks run, with read-only payloads; at most 5 runs in flight per org.
- A `target_token` is kept only in memory until its run finishes, and is redacted from evidence.
- Every change is written to the org's append-only audit log; evidence is write-once and stored with its SHA-256.
