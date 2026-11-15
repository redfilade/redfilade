package pack

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/redfilade/redfilade/internal/scenario"
)

func manifest(pinned bool) *scenario.Manifest {
	img := "x/y:1"
	if pinned {
		img = "x/y@sha256:" + strings.Repeat("a", 64)
	}
	return &scenario.Manifest{ID: "community-pack", Builds: scenario.Builds{Vulnerable: scenario.Build{Image: img}, Secure: scenario.Build{Image: img + "x"}}}
}

func TestDigestIsExactBytes(t *testing.T) {
	a, b := Digest([]byte(`{"a":1}`)), Digest([]byte(`{"a": 1}`))
	if a == b || !strings.HasPrefix(a, "sha256:") || len(a) != 71 {
		t.Fatalf("digests %s %s", a, b)
	}
}

func TestDecide(t *testing.T) {
	d := "sha256:" + strings.Repeat("b", 64)
	allow := map[string]bool{d: true}
	cases := []struct {
		name string
		m    *scenario.Manifest
		sig  string
		p    Policy
		ok   bool
	}{
		{"invalid signature never runs", manifest(true), Invalid, Policy{AllowUnsigned: true, Confirm: "community-pack", Interactive: true}, false},
		{"verified + pinned, interactive", manifest(true), Verified, Policy{Interactive: true}, true},
		{"verified but unpinned", manifest(false), Verified, Policy{Interactive: true}, false},
		{"unsigned refused by default", manifest(true), Unsigned, Policy{Interactive: true}, false},
		{"unsigned, wrong confirmation", manifest(true), Unsigned, Policy{AllowUnsigned: true, Confirm: "communitypack", Interactive: true}, false},
		{"unsigned, confirmed", manifest(false), Unsigned, Policy{AllowUnsigned: true, Confirm: "community-pack", Interactive: true}, true},
		{"unverifiable treated as unsigned", manifest(true), Unverifiable, Policy{Interactive: true}, false},
		{"CI without digest", manifest(true), Verified, Policy{}, false},
		{"CI with digest", manifest(true), Verified, Policy{AllowedDigests: allow}, true},
		{"CI unsigned needs both", manifest(true), Unsigned, Policy{AllowedDigests: allow}, false},
		{"CI unsigned with both", manifest(true), Unsigned, Policy{AllowUnsigned: true, Confirm: "community-pack", AllowedDigests: allow}, true},
	}
	for _, c := range cases {
		err := Decide(c.m, d, c.sig, c.p)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v", c.name, err)
		}
		if err != nil && !errors.Is(err, ErrRefused) {
			t.Errorf("%s: error is not ErrRefused", c.name)
		}
	}
}

func TestCheckStates(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, scenario.FileName), []byte("{}"), 0o644)
	v := Verifier{Cosign: "/nonexistent/cosign"}
	if s, _ := v.Check(context.Background(), dir); s != Unsigned {
		t.Fatalf("no bundle: %s", s)
	}
	_ = os.WriteFile(filepath.Join(dir, BundleName), []byte("{}"), 0o644)
	if s, _ := (Verifier{Cosign: ""}).Check(context.Background(), dir); s != Unverifiable && s != Invalid {
		t.Fatalf("bundle without cosign: %s", s)
	}
	// A cosign that fails verification makes the pack invalid.
	fake := filepath.Join(dir, "cosign")
	_ = os.WriteFile(fake, []byte("#!/bin/sh\necho 'none of the expected identities matched' >&2\nexit 1\n"), 0o755)
	s, err := (Verifier{Cosign: fake}).Check(context.Background(), dir)
	if s != Invalid || err == nil || !strings.Contains(err.Error(), "identities") {
		t.Fatalf("failing cosign: %s %v", s, err)
	}
	ok := filepath.Join(dir, "cosign-ok")
	_ = os.WriteFile(ok, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if s, _ := (Verifier{Cosign: ok}).Check(context.Background(), dir); s != Verified {
		t.Fatalf("passing cosign: %s", s)
	}
}

func TestAllowlist(t *testing.T) {
	p := filepath.Join(t.TempDir(), "allow.txt")
	d := "sha256:" + strings.Repeat("c", 64)
	_ = os.WriteFile(p, []byte("# packs we trust\n"+d+"  # community-pack\n\n"), 0o644)
	m, err := ParseAllowlist(p)
	if err != nil || !m[d] || len(m) != 1 {
		t.Fatalf("allowlist = %v %v", m, err)
	}
	_ = os.WriteFile(p, []byte("not-a-digest\n"), 0o644)
	if _, err := ParseAllowlist(p); err == nil {
		t.Fatal("bad line accepted")
	}
}
