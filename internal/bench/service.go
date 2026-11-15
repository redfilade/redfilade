package bench

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/redfilade/redfilade/internal/domain"
	"github.com/redfilade/redfilade/internal/oracle"
	"github.com/redfilade/redfilade/internal/report"
	"github.com/redfilade/redfilade/internal/run"
)

// Service is the Test Bench API and its workers.
type Service struct {
	Store    *Store
	Verifier *domain.Verifier     // checks published proofs
	Remote   domain.RemoteOptions // address policy; zero value is strict
	Deadline time.Duration        // per run; default 5 minutes
	Version  string
	Log      *slog.Logger

	tokens sync.Map // run id -> target bearer token, memory only
}

var reUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// MaxBody bounds request bodies.
const MaxBody = 64 << 10

// Handler returns the HTTP API.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.Handle("POST /v1/domains", s.auth("tester", s.postDomain))
	mux.Handle("GET /v1/domains", s.auth("viewer", s.listDomains))
	mux.Handle("POST /v1/domains/{domain}/verify", s.auth("tester", s.verifyDomain))
	mux.Handle("POST /v1/runs", s.auth("tester", s.postRun))
	mux.Handle("GET /v1/runs", s.auth("viewer", s.listRuns))
	mux.Handle("GET /v1/runs/{id}", s.auth("viewer", s.getRun))
	mux.Handle("GET /v1/runs/{id}/evidence", s.auth("viewer", s.getEvidence))
	mux.Handle("POST /v1/keys", s.auth("admin", s.postKey))
	return mux
}

var roleRank = map[string]int{"viewer": 1, "tester": 2, "admin": 3}

type handler func(w http.ResponseWriter, r *http.Request, p *Principal)

func (s *Service) auth(min string, h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="redfilade"`)
			writeErr(w, 401, "an API key is required")
			return
		}
		p, err := s.Store.Authenticate(r.Context(), key)
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				s.logErr("authenticate", err)
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="redfilade", error="invalid_token"`)
			writeErr(w, 401, "invalid API key")
			return
		}
		if roleRank[p.Role] < roleRank[min] {
			writeErr(w, 403, "this key's role cannot do that")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
		h(w, r, p)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decode(r *http.Request, v any) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return errors.New("request body must be a JSON object with only the documented fields")
	}
	return nil
}

func (s *Service) logErr(what string, err error) {
	if s.Log != nil {
		s.Log.Error(what, "error", err.Error())
	}
}

// --- domains ---------------------------------------------------------------------

type domainView struct {
	Domain     string     `json:"domain"`
	Token      string     `json:"token"`
	DNSName    string     `json:"dns_txt_name"`
	HTTPSURL   string     `json:"https_url"`
	Method     string     `json:"method,omitempty"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
}

func view(r *domain.Record) domainView {
	v := domainView{Domain: r.Domain, Token: r.Token, DNSName: domain.DNSPrefix + r.Domain, HTTPSURL: "https://" + r.Domain + domain.WellKnownPath, Method: r.Method}
	if !r.VerifiedAt.IsZero() {
		t := r.VerifiedAt
		v.VerifiedAt = &t
	}
	return v
}

func (s *Service) postDomain(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in struct {
		Domain string `json:"domain"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	rec, err := s.Store.ChallengeDomain(r.Context(), p, in.Domain)
	if err != nil {
		if strings.Contains(err.Error(), "not a domain") || strings.Contains(err.Error(), "IP address") {
			writeErr(w, 400, err.Error())
			return
		}
		s.logErr("challenge", err)
		writeErr(w, 500, "could not create the challenge")
		return
	}
	writeJSON(w, 201, view(rec))
}

func (s *Service) listDomains(w http.ResponseWriter, r *http.Request, p *Principal) {
	recs, err := s.Store.Domains(r.Context(), p.OrgID)
	if err != nil {
		s.logErr("domains", err)
		writeErr(w, 500, "could not list domains")
		return
	}
	out := []domainView{}
	for _, rec := range recs {
		out = append(out, view(rec))
	}
	writeJSON(w, 200, out)
}

func (s *Service) verifyDomain(w http.ResponseWriter, r *http.Request, p *Principal) {
	d, err := domain.Normalize(r.PathValue("domain"))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	recs, err := s.Store.Domains(r.Context(), p.OrgID)
	if err != nil {
		s.logErr("domains", err)
		writeErr(w, 500, "could not read domains")
		return
	}
	rec, ok := recs[d]
	if !ok {
		writeErr(w, 404, "no challenge for this domain; POST /v1/domains first")
		return
	}
	method, err := s.Verifier.CheckProof(r.Context(), d, rec.Token)
	if err != nil {
		writeErr(w, 422, "the proof is not published yet: "+err.Error())
		return
	}
	if err := s.Store.MarkVerified(r.Context(), p, d, method); err != nil {
		s.logErr("verify", err)
		writeErr(w, 500, "could not record the verification")
		return
	}
	rec.Method, rec.VerifiedAt = method, time.Now().UTC()
	writeJSON(w, 200, view(rec))
}

// --- runs ---------------------------------------------------------------------------

func (s *Service) postRun(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in struct {
		URL         string `json:"url"`
		Level       string `json:"level"`
		Protocol    string `json:"protocol"`
		TargetToken string `json:"target_token"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if in.Level == "" {
		in.Level = "L2"
	}
	if in.Protocol == "" {
		in.Protocol = "2026-07-28"
	}
	if in.Level != "L1" && in.Level != "L2" {
		writeErr(w, 400, "level must be L1 or L2")
		return
	}
	if in.Protocol != "2026-07-28" && in.Protocol != "2025-11-25" {
		writeErr(w, 400, "protocol must be 2026-07-28 or 2025-11-25")
		return
	}
	if len(in.TargetToken) > 4096 {
		writeErr(w, 400, "target_token is too long")
		return
	}
	u, err := url.Parse(in.URL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || len(in.URL) > 2048 {
		writeErr(w, 400, "url must be an https URL without credentials")
		return
	}
	if net.ParseIP(u.Hostname()) != nil || strings.EqualFold(u.Hostname(), "localhost") {
		writeErr(w, 400, "the hosted Test Bench only tests verified domain names, never IP addresses or localhost")
		return
	}
	recs, err := s.Store.Domains(r.Context(), p.OrgID)
	if err != nil {
		s.logErr("domains", err)
		writeErr(w, 500, "could not read domains")
		return
	}
	if _, err := s.Verifier.AuthorizeRecords(r.Context(), u.Hostname(), recs); err != nil {
		writeErr(w, 403, err.Error())
		return
	}
	run, err := s.Store.CreateRun(r.Context(), p, u.String(), in.Level, in.Protocol)
	if errors.Is(err, ErrBusy) {
		writeErr(w, 429, err.Error())
		return
	}
	if err != nil {
		s.logErr("create run", err)
		writeErr(w, 500, "could not queue the run")
		return
	}
	if in.TargetToken != "" {
		s.tokens.Store(run.ID, in.TargetToken)
	}
	writeJSON(w, 202, run)
}

func (s *Service) listRuns(w http.ResponseWriter, r *http.Request, p *Principal) {
	runs, err := s.Store.ListRuns(r.Context(), p.OrgID, 100)
	if err != nil {
		s.logErr("runs", err)
		writeErr(w, 500, "could not list runs")
		return
	}
	if runs == nil {
		runs = []*Run{}
	}
	writeJSON(w, 200, runs)
}

func (s *Service) getRun(w http.ResponseWriter, r *http.Request, p *Principal) {
	id := r.PathValue("id")
	if !reUUID.MatchString(id) {
		writeErr(w, 404, "no such run")
		return
	}
	run, err := s.Store.GetRun(r.Context(), p.OrgID, id)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, 404, "no such run")
		return
	}
	if err != nil {
		s.logErr("run", err)
		writeErr(w, 500, "could not read the run")
		return
	}
	writeJSON(w, 200, run)
}

func (s *Service) getEvidence(w http.ResponseWriter, r *http.Request, p *Principal) {
	id := r.PathValue("id")
	if !reUUID.MatchString(id) {
		writeErr(w, 404, "no such run")
		return
	}
	ev, err := s.Store.Evidence(r.Context(), p.OrgID, id)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, 404, "no evidence for this run")
		return
	}
	if err != nil {
		s.logErr("evidence", err)
		writeErr(w, 500, "could not read the evidence")
		return
	}
	writeJSON(w, 200, ev)
}

func (s *Service) postKey(w http.ResponseWriter, r *http.Request, p *Principal) {
	var in struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if roleRank[in.Role] == 0 || len(in.Name) == 0 || len(in.Name) > 100 {
		writeErr(w, 400, "name (1-100 characters) and role (admin, tester or viewer) are required")
		return
	}
	key, err := s.Store.CreateKey(r.Context(), p, in.Name, in.Role)
	if err != nil {
		s.logErr("key", err)
		writeErr(w, 500, "could not create the key")
		return
	}
	writeJSON(w, 201, map[string]string{"key": key, "note": "store this key now: it is not shown again"})
}

// --- workers --------------------------------------------------------------------------

// Work runs n workers until ctx ends. Each claims queued runs and executes them.
func (s *Service) Work(ctx context.Context, n int) {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				if !s.WorkOnce(ctx) {
					select {
					case <-ctx.Done():
					case <-time.After(500 * time.Millisecond):
					}
				}
			}
		}()
	}
	wg.Wait()
}

// WorkOnce runs at most one queued run and reports whether it found one.
func (s *Service) WorkOnce(ctx context.Context) bool {
	id, org, err := s.Store.Claim(ctx)
	if err != nil {
		s.logErr("claim", err)
		return false
	}
	if id == "" {
		return false
	}
	tok, _ := s.tokens.LoadAndDelete(id)
	token, _ := tok.(string)
	status, verdict, errText, pinned, evidence := s.execute(ctx, org, id, token)
	if err := s.Store.Finish(context.Background(), org, id, status, verdict, errText, pinned, evidence); err != nil {
		s.logErr("finish", err)
	}
	return true
}

func (s *Service) execute(ctx context.Context, org, id, token string) (status, verdict, errText, pinned string, evidence []byte) {
	r, err := s.Store.GetRun(ctx, org, id)
	if err != nil {
		return "error", "", "run disappeared: " + err.Error(), "", nil
	}
	u, err := url.Parse(r.URL)
	if err != nil {
		return "error", "", "invalid url", "", nil
	}
	recs, err := s.Store.Domains(ctx, org)
	if err != nil {
		return "error", "", "could not read domains", "", nil
	}
	// Ownership and the address are checked again at run time, not only when queued.
	hc, _, addr, err := s.Verifier.RemoteClientPinned(ctx, u.Hostname(), recs, s.Remote)
	if err != nil {
		return "error", "", err.Error(), "", nil
	}
	deadline := s.Deadline
	if deadline == 0 {
		deadline = 5 * time.Minute
	}
	ev, err := run.Remote(ctx, run.RemoteOptions{URL: r.URL, Token: token, HTTPClient: hc}, r.Protocol, r.Level,
		run.Options{Deadline: deadline, Version: s.Version})
	if err != nil {
		return "error", "", err.Error(), addr.String(), nil
	}
	var buf bytes.Buffer
	if err := report.WriteEvidence(&buf, ev); err != nil {
		return "error", "", "could not encode evidence", addr.String(), nil
	}
	switch ev.Oracle.Verdict {
	case oracle.Exploited:
		status = "failed"
	case oracle.NotExploited:
		status = "passed"
	default:
		status = "error"
	}
	if len(ev.Errors) > 0 {
		errText = fmt.Sprint(ev.Errors)
	}
	return status, ev.Oracle.Verdict, errText, addr.String(), buf.Bytes()
}
