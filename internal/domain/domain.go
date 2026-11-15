// Package domain proves that the user controls a domain before Redfilade
// sends attack traffic to it (ADR-0010).
//
// A challenge token is published either as a DNS TXT record at
// _redfilade-challenge.<domain> or as the body of
// https://<domain>/.well-known/redfilade-challenge. A DNS proof covers the
// domain and its subdomains (it shows control of the zone); a file proof
// covers only that exact host. Proofs are checked again, live, before every
// remote run, and a verified host is only tested at public IP addresses,
// pinned for the whole run.
package domain

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Where challenges are published.
const (
	DNSPrefix     = "_redfilade-challenge."
	WellKnownPath = "/.well-known/redfilade-challenge"
	TokenPrefix   = "redfilade-verify="
)

// Methods of proof.
const (
	MethodDNS  = "dns"
	MethodHTTP = "https"
)

var (
	// ErrNotVerified means no current proof was found for a host.
	ErrNotVerified = errors.New("domain not verified")
	reDomain       = regexp.MustCompile(`^(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

// Record is one domain in the local store.
type Record struct {
	Domain     string    `json:"domain"`
	Token      string    `json:"token"`
	CreatedAt  time.Time `json:"created_at"`
	VerifiedAt time.Time `json:"verified_at,omitempty"`
	Method     string    `json:"method,omitempty"`
}

// Verifier checks proofs. Its lookups can be replaced in tests.
type Verifier struct {
	LookupTXT  func(ctx context.Context, name string) ([]string, error)
	HTTPClient *http.Client
	Dir        string // where domains.json lives
}

// NewVerifier returns a verifier using the system resolver, a strict HTTPS
// client and the user's config directory (REDFILADE_CONFIG_DIR overrides it).
func NewVerifier() (*Verifier, error) {
	dir := os.Getenv("REDFILADE_CONFIG_DIR")
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return nil, err
		}
		dir = filepath.Join(base, "redfilade")
	}
	r := &net.Resolver{}
	return &Verifier{
		LookupTXT: r.LookupTXT,
		HTTPClient: &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		Dir: dir,
	}, nil
}

// Normalize lower-cases a domain and checks its shape. IP addresses are not
// domains: ownership of an address cannot be proven this way.
func Normalize(d string) (string, error) {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if !reDomain.MatchString(d) || len(d) > 253 {
		return "", fmt.Errorf("%q is not a domain name", d)
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "", fmt.Errorf("%q is an IP address; verify a domain name instead", d)
	}
	return d, nil
}

func (v *Verifier) path() string { return filepath.Join(v.Dir, "domains.json") }

func (v *Verifier) load() (map[string]*Record, error) {
	out := map[string]*Record{}
	b, err := os.ReadFile(v.path())
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, errors.New("domains.json is too large")
	}
	var list []*Record
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("domains.json: %w", err)
	}
	for _, r := range list {
		out[r.Domain] = r
	}
	return out, nil
}

func (v *Verifier) save(m map[string]*Record) error {
	if err := os.MkdirAll(v.Dir, 0o700); err != nil {
		return err
	}
	if st, err := os.Lstat(v.path()); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to write domains.json through a symlink")
	}
	var list []*Record
	for _, r := range m {
		list = append(list, r)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := v.path() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, v.path())
}

// Challenge returns the token to publish for d, creating one if needed.
func (v *Verifier) Challenge(d string) (*Record, error) {
	d, err := Normalize(d)
	if err != nil {
		return nil, err
	}
	m, err := v.load()
	if err != nil {
		return nil, err
	}
	if r, ok := m[d]; ok {
		return r, nil
	}
	tok, err := NewToken()
	if err != nil {
		return nil, err
	}
	r := &Record{Domain: d, Token: tok, CreatedAt: time.Now().UTC()}
	m[d] = r
	return r, v.save(m)
}

// Verify checks the published proof for d and records the result.
func (v *Verifier) Verify(ctx context.Context, d string) (*Record, error) {
	d, err := Normalize(d)
	if err != nil {
		return nil, err
	}
	m, err := v.load()
	if err != nil {
		return nil, err
	}
	r, ok := m[d]
	if !ok {
		return nil, fmt.Errorf("no challenge for %s: run `redfilade domain challenge %s` first", d, d)
	}
	method, err := v.check(ctx, d, r.Token)
	if err != nil {
		return nil, err
	}
	r.Method, r.VerifiedAt = method, time.Now().UTC()
	return r, v.save(m)
}

// check returns the method whose proof is currently published.
func (v *Verifier) check(ctx context.Context, d, token string) (string, error) {
	if txts, err := v.LookupTXT(ctx, DNSPrefix+d); err == nil {
		for _, t := range txts {
			if strings.TrimSpace(t) == token {
				return MethodDNS, nil
			}
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+d+WellKnownPath, nil)
	if err == nil {
		if resp, err := v.HTTPClient.Do(req); err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && strings.TrimSpace(string(body)) == token {
				return MethodHTTP, nil
			}
		}
	}
	return "", fmt.Errorf("%w: %s: no TXT record %q at %s%s and no matching %s", ErrNotVerified, d, token, DNSPrefix, d, "https://"+d+WellKnownPath)
}

// CheckProof returns the method whose proof for d is currently published.
func (v *Verifier) CheckProof(ctx context.Context, d, token string) (string, error) {
	return v.check(ctx, d, token)
}

// NewToken returns a fresh challenge token.
func NewToken() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return TokenPrefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}

// Authorize returns the verified record that covers host, after checking
// live that its proof is still published. DNS proofs cover subdomains;
// HTTPS proofs cover only their exact host.
func (v *Verifier) Authorize(ctx context.Context, host string) (*Record, error) {
	m, err := v.load()
	if err != nil {
		return nil, err
	}
	return v.AuthorizeRecords(ctx, host, m)
}

// AuthorizeRecords is Authorize over records held elsewhere (the hosted
// service keeps them per organisation in its database).
func (v *Verifier) AuthorizeRecords(ctx context.Context, host string, m map[string]*Record) (*Record, error) {
	host, err := Normalize(host)
	if err != nil {
		return nil, err
	}
	for d := host; ; {
		if r, ok := m[d]; ok && !r.VerifiedAt.IsZero() && (r.Method == MethodDNS || d == host) {
			method, err := v.check(ctx, d, r.Token)
			if err != nil {
				return nil, fmt.Errorf("%s was verified before, but its proof is no longer published: %w", d, err)
			}
			if method == MethodHTTP && d != host {
				return nil, fmt.Errorf("%w: an HTTPS file proof for %s does not cover %s; publish a DNS TXT record instead", ErrNotVerified, d, host)
			}
			return r, nil
		}
		i := strings.IndexByte(d, '.')
		if i < 0 || !strings.Contains(d[i+1:], ".") {
			break
		}
		d = d[i+1:]
	}
	return nil, fmt.Errorf("%w: %s (run `redfilade domain challenge` and `redfilade domain verify`)", ErrNotVerified, host)
}

// List returns every record in the store.
func (v *Verifier) List() ([]*Record, error) {
	m, err := v.load()
	if err != nil {
		return nil, err
	}
	var out []*Record
	for _, r := range m {
		out = append(out, r)
	}
	return out, nil
}

// PublicAddr reports whether an address is safe to send remote tests to: not
// loopback, private, link-local (cloud metadata), multicast, unspecified,
// shared (CGNAT) or otherwise reserved.
func PublicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range reserved {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

var reserved = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "64:ff9b::/96", "100::/64", "2001:db8::/32", "fc00::/7"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// PinnedDialer resolves host once, refuses non-public addresses, and returns
// a DialContext that always connects to that address, so DNS cannot be used
// to move the run to another machine halfway through.
// allow decides which addresses are acceptable; nil means PublicAddr.
func PinnedDialer(ctx context.Context, host string, lookup func(ctx context.Context, host string) ([]netip.Addr, error),
	allow func(netip.Addr) bool) (func(ctx context.Context, network, addr string) (net.Conn, error), netip.Addr, error) {
	if allow == nil {
		allow = PublicAddr
	}
	if lookup == nil {
		lookup = func(ctx context.Context, h string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", h)
		}
	}
	addrs, err := lookup(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil, netip.Addr{}, fmt.Errorf("resolve %s: %v", host, err)
	}
	for _, a := range addrs {
		if !allow(a) {
			return nil, netip.Addr{}, fmt.Errorf("%s resolves to %s, which is not a public address; remote tests never target private networks", host, a)
		}
	}
	pinned := addrs[0].Unmap()
	d := &net.Dialer{Timeout: 10 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		return d.DialContext(ctx, network, net.JoinHostPort(pinned.String(), port))
	}, pinned, nil
}

// RemoteOptions configure RemoteClient. Zero values mean the strict defaults.
type RemoteOptions struct {
	Lookup  func(ctx context.Context, host string) ([]netip.Addr, error) // nil: system resolver
	Allow   func(netip.Addr) bool                                        // nil: PublicAddr
	RootCAs *x509.CertPool                                               // nil: system roots
}

// RemoteClient checks that host is covered by one of records (with a live
// proof re-check), resolves it to public addresses only, and returns an HTTPS
// client pinned to one of them, with a sentence explaining why the host may
// be tested.
func (v *Verifier) RemoteClient(ctx context.Context, host string, records map[string]*Record, o RemoteOptions) (*http.Client, string, error) {
	hc, proof, _, err := v.RemoteClientPinned(ctx, host, records, o)
	return hc, proof, err
}

// RemoteClientPinned is RemoteClient that also returns the pinned address.
func (v *Verifier) RemoteClientPinned(ctx context.Context, host string, records map[string]*Record, o RemoteOptions) (*http.Client, string, netip.Addr, error) {
	rec, err := v.AuthorizeRecords(ctx, host, records)
	if err != nil {
		return nil, "", netip.Addr{}, err
	}
	dial, pinned, err := PinnedDialer(ctx, host, o.Lookup, o.Allow)
	if err != nil {
		return nil, "", netip.Addr{}, err
	}
	tr := &http.Transport{DialContext: dial, Proxy: nil, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: 8, TLSClientConfig: &tls.Config{RootCAs: o.RootCAs, MinVersion: tls.VersionTLS12}}
	proof := fmt.Sprintf("verified domain %s (%s proof, re-checked just now), connecting only to %s", rec.Domain, rec.Method, pinned)
	return &http.Client{Transport: tr}, proof, pinned, nil
}

// Records returns the local store as a map for AuthorizeRecords.
func (v *Verifier) Records() (map[string]*Record, error) { return v.load() }
