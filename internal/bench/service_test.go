package bench

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/redfilade/redfilade/internal/domain"
	"github.com/redfilade/redfilade/internal/pg"
	"github.com/redfilade/redfilade/internal/pg/pgtest"
)

// appURL migrates a fresh database as the owner and returns a URL for a
// login role that is a member of redfilade_app (no BYPASSRLS), as in production.
func appURL(t *testing.T) string {
	ctx := context.Background()
	owner := pgtest.URL(t)
	c, err := pg.Connect(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := Migrate(ctx, c); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	role, pw := "bench_"+hex.EncodeToString(b), hex.EncodeToString(append(b, b...))
	// role and pw are hex generated here, never input.
	if err := c.Script(ctx, "CREATE ROLE "+role+" LOGIN PASSWORD '"+pw+"' IN ROLE redfilade_app"); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(owner)
	if err := c.Script(ctx, "GRANT CONNECT ON DATABASE "+strings.TrimPrefix(u.Path, "/")+" TO "+role); err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(role, pw)
	return u.String()
}

func mintJWT(secret, aud string) string {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
	c, _ := json.Marshal(map[string]any{"sub": "builder", "aud": aud, "exp": time.Now().Add(time.Hour).Unix()})
	unsigned := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(unsigned))
	return unsigned + "." + enc.EncodeToString(m.Sum(nil))
}

// twin starts the http-auth twin and a TLS front end for it; it returns the
// backend URL (the twin's resource) and the front end.
func twin(t *testing.T, mode, secret string) (string, *httptest.Server) {
	root, _ := filepath.Abs("../..")
	bin := filepath.Join(t.TempDir(), "http-auth")
	b := exec.Command("go", "build", "-ldflags", "-X main.mode="+mode, "-o", bin, "./targets/http-auth")
	b.Dir = root
	if out, err := b.CombinedOutput(); err != nil {
		t.Fatalf("build twin: %v\n%s", err, out)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	backend := "http://" + addr + "/mcp"
	cmd := exec.Command(bin)
	cmd.Env = []string{"ADDR=" + addr, "RESOURCE=" + backend, "JWT_SECRET=" + secret}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	front := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: addr}))
	t.Cleanup(front.Close)
	return backend, front
}

type client struct {
	t    *testing.T
	base string
	key  string
}

func (c client) do(method, path string, body any) (int, map[string]any) {
	c.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, r)
	if c.key != "" {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = map[string]any{"_raw": string(b)}
	}
	return resp.StatusCode, out
}

func TestBenchEndToEnd(t *testing.T) {
	ctx := context.Background()
	pool := pg.NewPool(appURL(t), 4)
	defer pool.Close()
	store := NewStore(pool)
	orgA, keyA, err := store.CreateOrg(ctx, "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	_, keyB, err := store.CreateOrg(ctx, "globex", "Globex")
	if err != nil {
		t.Fatal(err)
	}

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	secret := hex.EncodeToString(key)
	vulnBackend, vulnFront := twin(t, "vulnerable", secret)
	secBackend, secFront := twin(t, "secure", secret)
	roots := x509.NewCertPool()
	roots.AddCert(vulnFront.Certificate())
	roots.AddCert(secFront.Certificate())

	txt := map[string][]string{}
	svc := &Service{
		Store: store,
		Verifier: &domain.Verifier{LookupTXT: func(_ context.Context, name string) ([]string, error) {
			if v, ok := txt[name]; ok {
				return v, nil
			}
			return nil, errors.New("no such host")
		}, HTTPClient: &http.Client{Timeout: time.Second}},
		// Tests serve the twins on loopback; production keeps the strict
		// public-address policy.
		Remote: domain.RemoteOptions{Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}, Allow: func(netip.Addr) bool { return true }, RootCAs: roots},
		Deadline: time.Minute,
	}
	api := httptest.NewServer(svc.Handler())
	defer api.Close()
	a := client{t, api.URL, keyA}
	b := client{t, api.URL, keyB}

	// Authentication and roles.
	if code, _ := (client{t, api.URL, ""}).do("GET", "/v1/runs", nil); code != 401 {
		t.Fatalf("no key: %d", code)
	}
	if code, _ := (client{t, api.URL, "rfk_notreal_xxx"}).do("GET", "/v1/runs", nil); code != 401 {
		t.Fatalf("bad key: %d", code)
	}
	code, out := a.do("POST", "/v1/keys", map[string]string{"name": "dashboard", "role": "viewer"})
	if code != 201 {
		t.Fatalf("create viewer key: %d %v", code, out)
	}
	viewer := client{t, api.URL, out["key"].(string)}
	if code, _ := viewer.do("POST", "/v1/domains", map[string]string{"domain": "example.com"}); code != 403 {
		t.Fatalf("viewer may not write: %d", code)
	}

	// Domain verification.
	code, out = a.do("POST", "/v1/domains", map[string]string{"domain": "Example.COM"})
	if code != 201 || out["domain"] != "example.com" || out["dns_txt_name"] != "_redfilade-challenge.example.com" {
		t.Fatalf("challenge: %d %v", code, out)
	}
	token := out["token"].(string)
	port := func(s *httptest.Server) string { _, p, _ := net.SplitHostPort(s.Listener.Addr().String()); return p }
	vulnURL := "https://example.com:" + port(vulnFront) + "/mcp"
	secURL := "https://example.com:" + port(secFront) + "/mcp"
	if code, _ := a.do("POST", "/v1/runs", map[string]string{"url": vulnURL}); code != 403 {
		t.Fatalf("run before verification: %d", code)
	}
	if code, _ := a.do("POST", "/v1/domains/example.com/verify", nil); code != 422 {
		t.Fatalf("verify without proof: %d", code)
	}
	txt[domain.DNSPrefix+"example.com"] = []string{token}
	if code, out := a.do("POST", "/v1/domains/example.com/verify", nil); code != 200 || out["method"] != "dns" {
		t.Fatalf("verify: %d %v", code, out)
	}
	for _, bad := range []map[string]string{
		{"url": "https://127.0.0.1/mcp"}, {"url": "https://localhost/mcp"}, {"url": "http://example.com/mcp"},
		{"url": vulnURL, "level": "L3"}, {"url": "https://user:pw@example.com/mcp"},
	} {
		if code, out := a.do("POST", "/v1/runs", bad); code != 400 {
			t.Errorf("%v: %d %v", bad, code, out)
		}
	}
	if code, out := a.do("POST", "/v1/runs", map[string]any{"url": vulnURL, "extra": 1}); code != 400 {
		t.Errorf("unknown field accepted: %d %v", code, out)
	}
	if code, out := b.do("POST", "/v1/runs", map[string]string{"url": vulnURL}); code != 403 {
		t.Fatalf("another org's domain: %d %v", code, out)
	}

	// Queue a run against each twin and let a worker execute them.
	ids := map[string]string{}
	for name, target := range map[string]struct{ url, backend string }{"vulnerable": {vulnURL, vulnBackend}, "secure": {secURL, secBackend}} {
		code, out := a.do("POST", "/v1/runs", map[string]string{"url": target.url, "level": "L2", "target_token": mintJWT(secret, target.backend)})
		if code != 202 || out["status"] != "queued" {
			t.Fatalf("%s run: %d %v", name, code, out)
		}
		ids[name] = out["id"].(string)
	}
	for svc.WorkOnce(ctx) {
	}
	for name, want := range map[string]string{"vulnerable": "failed", "secure": "passed"} {
		code, out := a.do("GET", "/v1/runs/"+ids[name], nil)
		if code != 200 || out["status"] != want || out["pinned_addr"] != "127.0.0.1" {
			t.Fatalf("%s: %d %v", name, code, out)
		}
		code, ev := a.do("GET", "/v1/runs/"+ids[name]+"/evidence", nil)
		if code != 200 {
			t.Fatalf("%s evidence: %d", name, code)
		}
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), "eyJ") {
			t.Errorf("%s evidence holds a raw JWT", name)
		}
		if name == "vulnerable" && !strings.Contains(string(raw), "auth_bypassed") {
			t.Errorf("vulnerable evidence lacks auth_bypassed")
		}
	}

	// Tenant isolation through the API: Globex cannot see Acme's run.
	if code, _ := b.do("GET", "/v1/runs/"+ids["vulnerable"], nil); code != 404 {
		t.Fatalf("cross-org read: %d", code)
	}
	if code, _ := b.do("GET", "/v1/runs/"+ids["vulnerable"]+"/evidence", nil); code != 404 {
		t.Fatalf("cross-org evidence read: %d", code)
	}
	if code, _ := a.do("GET", "/v1/runs/not-a-uuid", nil); code != 404 {
		t.Fatalf("malformed id: %d", code)
	}

	// The target token never reached the database, and the audit log has the story.
	err = pool.With(ctx, func(c *pg.Conn) error {
		if _, err := c.Exec(ctx, "SELECT set_config('redfilade.org_id', $1, false)", orgA); err != nil {
			return err
		}
		r, err := c.Exec(ctx, "SELECT string_agg(action, ',' ORDER BY id) FROM redfilade.audit_log")
		if err != nil {
			return err
		}
		actions := *r.Data[0][0]
		for _, want := range []string{"org.create", "key.create", "domain.challenge", "domain.verify", "run.create", "run.finish"} {
			if !strings.Contains(actions, want) {
				t.Errorf("audit log lacks %s: %s", want, actions)
			}
		}
		r, err = c.Exec(ctx, "SELECT count(*) FROM redfilade.runs r JOIN redfilade.run_evidence e ON e.run_id = r.id WHERE r.target_url LIKE '%eyJ%' OR e.evidence LIKE '%eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ%'")
		if err != nil {
			return err
		}
		if *r.Data[0][0] != "0" {
			t.Error("a target token was stored")
		}
		_, err = c.Exec(ctx, "SELECT set_config('redfilade.org_id', '', false)")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBenchRefusesPrivateAddressesByDefault(t *testing.T) {
	ctx := context.Background()
	pool := pg.NewPool(appURL(t), 2)
	defer pool.Close()
	store := NewStore(pool)
	_, key, err := store.CreateOrg(ctx, "initech", "Initech")
	if err != nil {
		t.Fatal(err)
	}
	txt := map[string][]string{}
	svc := &Service{Store: store, Verifier: &domain.Verifier{LookupTXT: func(_ context.Context, n string) ([]string, error) { return txt[n], nil }, HTTPClient: &http.Client{}},
		// Default address policy; DNS answers with the cloud metadata address.
		Remote: domain.RemoteOptions{Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
		}}}
	api := httptest.NewServer(svc.Handler())
	defer api.Close()
	c := client{t, api.URL, key}
	_, out := c.do("POST", "/v1/domains", map[string]string{"domain": "example.org"})
	txt[domain.DNSPrefix+"example.org"] = []string{out["token"].(string)}
	c.do("POST", "/v1/domains/example.org/verify", nil)
	code, out := c.do("POST", "/v1/runs", map[string]string{"url": "https://example.org/mcp"})
	if code != 202 {
		t.Fatalf("queue: %d %v", code, out)
	}
	for svc.WorkOnce(ctx) {
	}
	_, got := c.do("GET", "/v1/runs/"+out["id"].(string), nil)
	if got["status"] != "error" || !strings.Contains(got["error"].(string), "not a public address") {
		t.Fatalf("metadata address should be refused at run time: %v", got)
	}
}
