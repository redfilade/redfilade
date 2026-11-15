package bench

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redfilade/redfilade/internal/domain"
	"github.com/redfilade/redfilade/internal/pg"
)

// ErrNotFound is returned for rows that do not exist in the caller's org.
var ErrNotFound = errors.New("not found")

// Store is the Test Bench's database access. Every org-scoped call runs in a
// transaction that first sets redfilade.org_id, so row-level security
// filters every statement even if the code has a bug.
type Store struct{ pool *pg.Pool }

// NewStore wraps a pool connected as the application role.
func NewStore(p *pg.Pool) *Store { return &Store{pool: p} }

// Principal is an authenticated API key.
type Principal struct {
	KeyID, OrgID, Role string
}

func (s *Store) inOrg(ctx context.Context, org string, f func(*pg.Conn) error) error {
	return s.pool.Tx(ctx, func(c *pg.Conn) error {
		if _, err := c.Exec(ctx, "SELECT set_config('redfilade.org_id', $1, true)", org); err != nil {
			return err
		}
		return f(c)
	})
}

// --- API keys ------------------------------------------------------------------

// KeyPrefix starts every API key.
const KeyPrefix = "rfk_"

// NewKey returns a key, its display prefix and its hash. The key is shown
// once; only the hash is stored.
func NewKey() (key, prefix string, hash []byte, err error) {
	b := make([]byte, 30)
	if _, err = rand.Read(b); err != nil {
		return
	}
	s := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
	prefix = KeyPrefix + s[:8]
	key = prefix + "_" + s[8:]
	h := sha256.Sum256([]byte(key))
	return key, prefix, h[:], nil
}

// Authenticate returns the principal for a key, or ErrNotFound.
func (s *Store) Authenticate(ctx context.Context, key string) (*Principal, error) {
	if !strings.HasPrefix(key, KeyPrefix) || len(key) > 100 {
		return nil, ErrNotFound
	}
	h := sha256.Sum256([]byte(key))
	var p *Principal
	err := s.pool.With(ctx, func(c *pg.Conn) error {
		r, err := c.Exec(ctx, "SELECT key_id, org_id, role FROM redfilade.authenticate_api_key($1)", h[:])
		if err != nil || len(r.Data) != 1 {
			return err
		}
		p = &Principal{KeyID: *r.Data[0][0], OrgID: *r.Data[0][1], Role: *r.Data[0][2]}
		return nil
	})
	if err == nil && p == nil {
		err = ErrNotFound
	}
	return p, err
}

// CreateOrg creates an organisation with a default project and an admin key,
// and returns the key. The org id is chosen first so that every insert
// passes the row-level-security check.
func (s *Store) CreateOrg(ctx context.Context, slug, name string) (orgID, key string, err error) {
	err = s.pool.Tx(ctx, func(c *pg.Conn) error {
		r, err := c.Exec(ctx, "SELECT redfilade.uuid_v7()::text")
		if err != nil {
			return err
		}
		orgID = *r.Data[0][0]
		if _, err := c.Exec(ctx, "SELECT set_config('redfilade.org_id', $1, true)", orgID); err != nil {
			return err
		}
		if _, err := c.Exec(ctx, "INSERT INTO redfilade.orgs (id, slug, name) VALUES ($1, $2, $3)", orgID, slug, name); err != nil {
			return err
		}
		if _, err := c.Exec(ctx, "INSERT INTO redfilade.projects (org_id, slug, name) VALUES ($1, 'default', 'Default')", orgID); err != nil {
			return err
		}
		var prefix string
		var hash []byte
		if key, prefix, hash, err = NewKey(); err != nil {
			return err
		}
		if _, err := c.Exec(ctx, "INSERT INTO redfilade.api_keys (org_id, name, prefix, key_hash, role) VALUES ($1, 'admin', $2, $3, 'admin')", orgID, prefix, hash); err != nil {
			return err
		}
		_, err = c.Exec(ctx, "INSERT INTO redfilade.audit_log (org_id, action, target) VALUES ($1, 'org.create', $2)", orgID, slug)
		return err
	})
	return orgID, key, err
}

// CreateKey adds an API key with a role to the caller's org.
func (s *Store) CreateKey(ctx context.Context, p *Principal, name, role string) (string, error) {
	var key string
	err := s.inOrg(ctx, p.OrgID, func(c *pg.Conn) error {
		k, prefix, hash, err := NewKey()
		if err != nil {
			return err
		}
		key = k
		if _, err := c.Exec(ctx, "INSERT INTO redfilade.api_keys (org_id, name, prefix, key_hash, role) VALUES ($1, $2, $3, $4, $5)", p.OrgID, name, prefix, hash, role); err != nil {
			return err
		}
		return audit(ctx, c, p, "key.create", prefix, map[string]any{"role": role})
	})
	return key, err
}

func audit(ctx context.Context, c *pg.Conn, p *Principal, action, target string, detail map[string]any) error {
	if detail == nil {
		detail = map[string]any{}
	}
	if p != nil {
		detail["api_key_id"] = p.KeyID
	}
	b, _ := json.Marshal(detail)
	_, err := c.Exec(ctx, "INSERT INTO redfilade.audit_log (org_id, action, target, detail) VALUES ($1, $2, $3, $4)",
		p.OrgID, action, target, json.RawMessage(b))
	return err
}

// --- domains ---------------------------------------------------------------------

// ChallengeDomain returns the org's challenge for d, creating it if needed.
func (s *Store) ChallengeDomain(ctx context.Context, p *Principal, d string) (*domain.Record, error) {
	d, err := domain.Normalize(d)
	if err != nil {
		return nil, err
	}
	var rec *domain.Record
	err = s.inOrg(ctx, p.OrgID, func(c *pg.Conn) error {
		existing, err := domains(ctx, c)
		if err != nil {
			return err
		}
		if r, ok := existing[d]; ok {
			rec = r
			return nil
		}
		tok, err := domain.NewToken()
		if err != nil {
			return err
		}
		if _, err := c.Exec(ctx, "INSERT INTO redfilade.domains (org_id, domain, token) VALUES ($1, $2, $3)", p.OrgID, d, tok); err != nil {
			return err
		}
		rec = &domain.Record{Domain: d, Token: tok, CreatedAt: time.Now().UTC()}
		return audit(ctx, c, p, "domain.challenge", d, nil)
	})
	return rec, err
}

// MarkVerified records a successful proof.
func (s *Store) MarkVerified(ctx context.Context, p *Principal, d, method string) error {
	return s.inOrg(ctx, p.OrgID, func(c *pg.Conn) error {
		r, err := c.Exec(ctx, "UPDATE redfilade.domains SET method = $2, verified_at = now() WHERE domain = $1", d, method)
		if err != nil {
			return err
		}
		if r.Affected() != 1 {
			return ErrNotFound
		}
		return audit(ctx, c, p, "domain.verify", d, map[string]any{"method": method})
	})
}

// Domains returns the org's domain records.
func (s *Store) Domains(ctx context.Context, org string) (map[string]*domain.Record, error) {
	var out map[string]*domain.Record
	err := s.inOrg(ctx, org, func(c *pg.Conn) error {
		var err error
		out, err = domains(ctx, c)
		return err
	})
	return out, err
}

func domains(ctx context.Context, c *pg.Conn) (map[string]*domain.Record, error) {
	r, err := c.Exec(ctx, "SELECT domain, token, coalesce(method, ''), verified_at, created_at FROM redfilade.domains")
	if err != nil {
		return nil, err
	}
	out := map[string]*domain.Record{}
	for _, row := range r.Data {
		rec := &domain.Record{Domain: *row[0], Token: *row[1], Method: *row[2]}
		if row[3] != nil {
			rec.VerifiedAt = parseTime(*row[3])
		}
		rec.CreatedAt = parseTime(*row[4])
		out[rec.Domain] = rec
	}
	return out, nil
}

func parseTime(s string) time.Time {
	for _, layout := range []string{"2006-01-02 15:04:05.999999-07", "2006-01-02 15:04:05.999999-07:00", "2006-01-02 15:04:05-07"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// --- runs ------------------------------------------------------------------------

// Run is one remote test.
type Run struct {
	ID         string     `json:"id"`
	Status     string     `json:"status"`
	Level      string     `json:"level"`
	URL        string     `json:"url"`
	Protocol   string     `json:"protocol"`
	Verdict    string     `json:"verdict,omitempty"`
	Error      string     `json:"error,omitempty"`
	PinnedAddr string     `json:"pinned_addr,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// MaxActiveRuns bounds queued and running runs per organisation.
const MaxActiveRuns = 5

// ErrBusy means the org already has MaxActiveRuns runs in flight.
var ErrBusy = errors.New("too many runs in flight for this organisation")

// CreateRun queues a remote test.
func (s *Store) CreateRun(ctx context.Context, p *Principal, url, level, protocol string) (*Run, error) {
	var run *Run
	err := s.inOrg(ctx, p.OrgID, func(c *pg.Conn) error {
		r, err := c.Exec(ctx, "SELECT count(*) FROM redfilade.runs WHERE status IN ('queued', 'running')")
		if err != nil {
			return err
		}
		if n, _ := strconv.Atoi(*r.Data[0][0]); n >= MaxActiveRuns {
			return ErrBusy
		}
		r, err = c.Exec(ctx, `INSERT INTO redfilade.runs (org_id, project_id, level, target_url, protocol, api_key_id)
SELECT $1, id, $2, $3, $4, $5 FROM redfilade.projects WHERE slug = 'default'
RETURNING id, created_at`, p.OrgID, level, url, protocol, p.KeyID)
		if err != nil {
			return err
		}
		if len(r.Data) != 1 {
			return errors.New("the organisation has no default project")
		}
		run = &Run{ID: *r.Data[0][0], Status: "queued", Level: level, URL: url, Protocol: protocol, CreatedAt: parseTime(*r.Data[0][1])}
		return audit(ctx, c, p, "run.create", run.ID, map[string]any{"url": url, "level": level})
	})
	return run, err
}

const runCols = "id, status, level, target_url, protocol, coalesce(verdict, ''), coalesce(error, ''), coalesce(pinned_addr, ''), created_at, finished_at"

func scanRun(row []*string) *Run {
	r := &Run{ID: *row[0], Status: *row[1], Level: *row[2], URL: *row[3], Protocol: *row[4], Verdict: *row[5], Error: *row[6], PinnedAddr: *row[7], CreatedAt: parseTime(*row[8])}
	if row[9] != nil {
		t := parseTime(*row[9])
		r.FinishedAt = &t
	}
	return r
}

// GetRun returns a run of the org.
func (s *Store) GetRun(ctx context.Context, org, id string) (*Run, error) {
	var run *Run
	err := s.inOrg(ctx, org, func(c *pg.Conn) error {
		r, err := c.Exec(ctx, "SELECT "+runCols+" FROM redfilade.runs WHERE id = $1::uuid", id)
		if err != nil {
			return err
		}
		if len(r.Data) == 0 {
			return ErrNotFound
		}
		run = scanRun(r.Data[0])
		return nil
	})
	return run, err
}

// ListRuns returns the org's most recent runs.
func (s *Store) ListRuns(ctx context.Context, org string, limit int) ([]*Run, error) {
	var out []*Run
	err := s.inOrg(ctx, org, func(c *pg.Conn) error {
		r, err := c.Exec(ctx, "SELECT "+runCols+" FROM redfilade.runs WHERE target_url IS NOT NULL ORDER BY id DESC LIMIT $1", limit)
		if err != nil {
			return err
		}
		for _, row := range r.Data {
			out = append(out, scanRun(row))
		}
		return nil
	})
	return out, err
}

// Evidence returns the stored evidence of a finished run.
func (s *Store) Evidence(ctx context.Context, org, id string) (json.RawMessage, error) {
	var ev json.RawMessage
	err := s.inOrg(ctx, org, func(c *pg.Conn) error {
		r, err := c.Exec(ctx, "SELECT evidence FROM redfilade.run_evidence WHERE run_id = $1::uuid", id)
		if err != nil {
			return err
		}
		if len(r.Data) == 0 {
			return ErrNotFound
		}
		ev = json.RawMessage(*r.Data[0][0])
		return nil
	})
	return ev, err
}

// Claim takes the next queued run for a worker.
func (s *Store) Claim(ctx context.Context) (runID, orgID string, err error) {
	err = s.pool.With(ctx, func(c *pg.Conn) error {
		r, err := c.Exec(ctx, "SELECT run_id, org_id FROM redfilade.claim_run()")
		if err != nil || len(r.Data) == 0 {
			return err
		}
		runID, orgID = *r.Data[0][0], *r.Data[0][1]
		return nil
	})
	return
}

// Finish stores a run's outcome and evidence (write-once).
func (s *Store) Finish(ctx context.Context, org, id, status, verdict, errText, pinned string, evidence []byte) error {
	return s.inOrg(ctx, org, func(c *pg.Conn) error {
		var v any
		if verdict != "" {
			v = verdict
		}
		var e any
		if errText != "" {
			if len(errText) > 2000 {
				errText = errText[:2000]
			}
			e = errText
		}
		var pin any
		if pinned != "" {
			pin = pinned
		}
		if _, err := c.Exec(ctx, "UPDATE redfilade.runs SET status = $2, verdict = $3, error = $4, pinned_addr = $5, finished_at = now() WHERE id = $1::uuid",
			id, status, v, e, pin); err != nil {
			return err
		}
		if evidence != nil {
			sum := sha256.Sum256(evidence)
			if _, err := c.Exec(ctx, "INSERT INTO redfilade.run_evidence (run_id, org_id, evidence, sha256) VALUES ($1::uuid, $2, $3, $4)",
				id, org, string(evidence), sum[:]); err != nil {
				return err
			}
		}
		_, err := c.Exec(ctx, "INSERT INTO redfilade.audit_log (org_id, action, target, detail) VALUES ($1, 'run.finish', $2, $3)",
			org, id, json.RawMessage(fmt.Sprintf(`{"status":%q,"verdict":%q}`, status, verdict)))
		return err
	})
}
