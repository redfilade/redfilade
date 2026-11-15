package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/redfilade/redfilade/internal/domain"
	"github.com/redfilade/redfilade/internal/sandbox"
)

// withDomainSeams points the CLI at a fake DNS, a temporary store and the
// given TLS roots, and resolves every host to 127.0.0.1.
func withDomainSeams(t *testing.T, txt map[string][]string, roots *x509.CertPool, allowLoopback bool) {
	dir := t.TempDir()
	oldV, oldL, oldA, oldR := domainVerifier, lookupNetIP, allowAddr, remoteRootCAs
	t.Cleanup(func() { domainVerifier, lookupNetIP, allowAddr, remoteRootCAs = oldV, oldL, oldA, oldR })
	domainVerifier = func() (*domain.Verifier, error) {
		v, err := domain.NewVerifier()
		if err != nil {
			return nil, err
		}
		v.Dir = dir
		v.LookupTXT = func(_ context.Context, name string) ([]string, error) {
			if r, ok := txt[name]; ok {
				return r, nil
			}
			return nil, errors.New("no such host")
		}
		return v, nil
	}
	lookupNetIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	if allowLoopback {
		allowAddr = func(netip.Addr) bool { return true }
	} else {
		allowAddr = nil
	}
	remoteRootCAs = roots
}

func cli(args ...string) (int, string) {
	var stdout, stderr bytes.Buffer
	code := Main(context.Background(), args, strings.NewReader(""), &stdout, &stderr, sandbox.Runner{})
	return code, stdout.String() + stderr.String()
}

func TestVerifiedDomainEndToEnd(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	secret := hex.EncodeToString(key)
	backend := startHTTPTwin(t, "secure", secret)
	target, _ := url.Parse(backend)
	front := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: target.Host}))
	defer front.Close()
	_, port, _ := strings.Cut(front.Listener.Addr().String(), ":")
	remote := "https://example.com:" + port + "/mcp"

	roots := x509.NewCertPool()
	roots.AddCert(front.Certificate())
	txt := map[string][]string{}
	withDomainSeams(t, txt, roots, true)

	if code, out := cli("test", "--url", remote, "--yes"); code != exitError || !strings.Contains(out, "not verified") {
		t.Fatalf("unverified domain: exit %d\n%s", code, out)
	}
	code, out := cli("domain", "challenge", "example.com")
	if code != exitPass {
		t.Fatalf("challenge: %d %s", code, out)
	}
	token := ""
	for _, f := range strings.Fields(out) {
		if strings.HasPrefix(f, domain.TokenPrefix) {
			token = f
		}
	}
	if code, _ := cli("domain", "verify", "example.com"); code != exitFindings {
		t.Fatal("verify should fail before the record exists")
	}
	txt[domain.DNSPrefix+"example.com"] = []string{token}
	if code, out := cli("domain", "verify", "example.com"); code != exitPass {
		t.Fatalf("verify: %d %s", code, out)
	}
	if code, out := cli("domain", "list"); code != exitPass || !strings.Contains(out, "verified (dns") {
		t.Fatalf("list: %s", out)
	}
	if code, out := cli("test", "--url", strings.Replace(remote, "https", "http", 1), "--yes"); code != exitError || !strings.Contains(out, "https") {
		t.Fatalf("plain http to a remote host: exit %d\n%s", code, out)
	}
	// The secure twin, behind TLS, on a verified domain: the run must pass.
	t.Setenv("REDFILADE_TEST_TOKEN", mintJWT(t, secret, backend))
	code, out = cli("test", "--url", remote, "--yes", "--level", "L2", "--token-env", "REDFILADE_TEST_TOKEN", "--out", t.TempDir())
	if !strings.Contains(out, "verified domain example.com (dns proof") || !strings.Contains(out, "connecting only to 127.0.0.1") {
		t.Fatalf("consent screen should name the proof and the pinned address:\n%s", out)
	}
	// The twin's configured resource is its backend URL, which is the token's
	// audience: every probe must be refused and the run must pass.
	if code != exitPass {
		t.Fatalf("verified run against the secure twin: exit %d\n%s", code, out)
	}

	// Removing the proof stops the next run.
	delete(txt, domain.DNSPrefix+"example.com")
	if code, out := cli("test", "--url", remote, "--yes"); code != exitError || !strings.Contains(out, "no longer published") {
		t.Fatalf("after removing the proof: exit %d\n%s", code, out)
	}
}

func TestVerifiedDomainOnPrivateAddressIsRefused(t *testing.T) {
	txt := map[string][]string{}
	withDomainSeams(t, txt, nil, false) // default policy: public addresses only
	_, out := cli("domain", "challenge", "example.com")
	for _, f := range strings.Fields(out) {
		if strings.HasPrefix(f, domain.TokenPrefix) {
			txt[domain.DNSPrefix+"example.com"] = []string{f}
		}
	}
	if code, out := cli("domain", "verify", "example.com"); code != exitPass {
		t.Fatal(out)
	}
	code, out := cli("test", "--url", "https://example.com/mcp", "--yes")
	if code != exitError || !strings.Contains(out, "not a public address") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}
