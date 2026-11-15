package domain

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDNS maps TXT names to records.
type fakeDNS map[string][]string

func (f fakeDNS) lookup(_ context.Context, name string) ([]string, error) {
	if v, ok := f[name]; ok {
		return v, nil
	}
	return nil, errors.New("no such host")
}

// httpsTo returns a client that sends every request for example.com and its
// subdomains to srv, trusting srv's test certificate.
func httpsTo(srv *httptest.Server) *http.Client {
	c := srv.Client()
	tr := c.Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	tr.TLSClientConfig = &tls.Config{RootCAs: tr.TLSClientConfig.RootCAs, ServerName: "example.com"}
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func newVerifier(t *testing.T, dns fakeDNS, srv *httptest.Server) *Verifier {
	v := &Verifier{LookupTXT: dns.lookup, Dir: t.TempDir(), HTTPClient: &http.Client{}}
	if srv != nil {
		v.HTTPClient = httpsTo(srv)
	}
	return v
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{"Example.COM.": "example.com", " api.example.com ": "api.example.com"} {
		if got, err := Normalize(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"localhost", "1.2.3.4", "exa mple.com", "-x.com", "", "a..b.com", "http://example.com"} {
		if _, err := Normalize(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDNSProofCoversSubdomains(t *testing.T) {
	dns := fakeDNS{}
	v := newVerifier(t, dns, nil)
	r, err := v.Challenge("example.com")
	if err != nil || !strings.HasPrefix(r.Token, TokenPrefix) {
		t.Fatal(r, err)
	}
	again, _ := v.Challenge("EXAMPLE.com")
	if again.Token != r.Token {
		t.Fatal("challenge should be stable")
	}
	if _, err := v.Verify(context.Background(), "example.com"); !errors.Is(err, ErrNotVerified) {
		t.Fatalf("verified without a proof: %v", err)
	}
	dns[DNSPrefix+"example.com"] = []string{"other", r.Token}
	if got, err := v.Verify(context.Background(), "example.com"); err != nil || got.Method != MethodDNS {
		t.Fatal(got, err)
	}
	for _, host := range []string{"example.com", "api.example.com", "a.b.example.com"} {
		if _, err := v.Authorize(context.Background(), host); err != nil {
			t.Errorf("%s: %v", host, err)
		}
	}
	for _, host := range []string{"example.org", "notexample.com", "example.com.evil.test"} {
		if _, err := v.Authorize(context.Background(), host); err == nil {
			t.Errorf("%s authorised", host)
		}
	}
	// Removing the record revokes authorisation on the next run.
	delete(dns, DNSPrefix+"example.com")
	if _, err := v.Authorize(context.Background(), "api.example.com"); err == nil {
		t.Fatal("authorised after the proof was removed")
	}
	st, err := os.Stat(filepath.Join(v.Dir, "domains.json"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("store permissions: %v %v", st, err)
	}
}

func TestHTTPSProofCoversOnlyItsHost(t *testing.T) {
	var token string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == WellKnownPath {
			w.Write([]byte(token + "\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	v := newVerifier(t, fakeDNS{}, srv)
	r, _ := v.Challenge("example.com")
	token = r.Token
	got, err := v.Verify(context.Background(), "example.com")
	if err != nil || got.Method != MethodHTTP {
		t.Fatal(got, err)
	}
	if _, err := v.Authorize(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Authorize(context.Background(), "api.example.com"); err == nil {
		t.Fatal("a file proof must not cover subdomains")
	}
	token = strings.ToUpper(r.Token) // a different value at the same place
	if _, err := v.Authorize(context.Background(), "example.com"); err == nil {
		t.Fatal("authorised with a changed file")
	}
}

func TestHTTPSProofIgnoresRedirects(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/token", http.StatusFound)
	}))
	defer srv.Close()
	v := newVerifier(t, fakeDNS{}, srv)
	v.Challenge("example.com")
	if _, err := v.Verify(context.Background(), "example.com"); err == nil {
		t.Fatal("a redirect must not count as a proof")
	}
}

func TestPublicAddr(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
		"::1", "fe80::1", "fd00::1", "::ffff:10.0.0.1", "224.0.0.1", "192.0.2.10", "198.18.0.1"} {
		if PublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s treated as public", s)
		}
	}
	for _, s := range []string{"93.184.215.14", "1.1.1.1", "2606:4700:4700::1111"} {
		if !PublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s treated as private", s)
		}
	}
}

func TestPinnedDialer(t *testing.T) {
	lookup := func(addrs ...string) func(context.Context, string) ([]netip.Addr, error) {
		return func(context.Context, string) ([]netip.Addr, error) {
			var out []netip.Addr
			for _, a := range addrs {
				out = append(out, netip.MustParseAddr(a))
			}
			return out, nil
		}
	}
	if _, _, err := PinnedDialer(context.Background(), "example.com", lookup("93.184.215.14", "10.0.0.1"), nil); err == nil {
		t.Fatal("a private address among the answers must be refused")
	}
	if _, _, err := PinnedDialer(context.Background(), "example.com", lookup("169.254.169.254"), nil); err == nil {
		t.Fatal("metadata address accepted")
	}
	// With an allow-list that admits loopback (tests only), the dialer pins.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		if c, err := l.Accept(); err == nil {
			c.Close()
		}
	}()
	dial, pinned, err := PinnedDialer(context.Background(), "example.com", lookup("127.0.0.1"), func(netip.Addr) bool { return true })
	if err != nil || pinned.String() != "127.0.0.1" {
		t.Fatal(pinned, err)
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	c, err := dial(context.Background(), "tcp", "example.com:"+port)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}
