// Package pack decides whether an external scenario pack may run
// (architecture record 10.3 and 10.4).
//
// Built-in scenarios ship inside the signed binary. A pack loaded from a
// directory is hostile until proven otherwise:
//
//   - its digest is the SHA-256 of the exact scenario.json bytes;
//   - a signature, if present, must verify against the identity of the
//     Redfilade release workflow, or the pack is refused outright;
//   - an unsigned pack runs only with --allow-unsigned and the pack id typed
//     to confirm (interactively) or passed with --confirm (CI);
//   - non-interactive runs must also list the pack's exact digest.
package pack

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/redfilade/redfilade/internal/scenario"
)

// BundleName is the Sigstore bundle stored next to scenario.json.
const BundleName = scenario.FileName + ".sigstore.json"

// Default trust: packs signed by the Redfilade release workflow.
const (
	DefaultIdentity = `^https://github\.com/redfilade/redfilade/\.github/workflows/release\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$`
	DefaultIssuer   = "https://token.actions.githubusercontent.com"
)

// Signature states.
const (
	Verified     = "verified"     // signature checked against the trusted identity
	Unsigned     = "unsigned"     // no signature bundle present
	Unverifiable = "unverifiable" // a bundle exists but cosign is not installed
	Invalid      = "invalid"      // the signature did not verify: never run
)

// Digest returns "sha256:<hex>" of the exact manifest bytes.
func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Verifier checks Sigstore bundles with the cosign CLI.
type Verifier struct {
	Cosign   string // path to cosign; "" means look it up on PATH
	Identity string // certificate identity regexp
	Issuer   string // OIDC issuer
}

// Check returns the signature state of the pack in dir.
func (v Verifier) Check(ctx context.Context, dir string) (string, error) {
	bundle := filepath.Join(dir, BundleName)
	if _, err := os.Stat(bundle); errors.Is(err, os.ErrNotExist) {
		return Unsigned, nil
	}
	bin := v.Cosign
	if bin == "" {
		var err error
		if bin, err = exec.LookPath("cosign"); err != nil {
			return Unverifiable, nil
		}
	}
	identity, issuer := v.Identity, v.Issuer
	if identity == "" {
		identity = DefaultIdentity
	}
	if issuer == "" {
		issuer = DefaultIssuer
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "verify-blob", filepath.Join(dir, scenario.FileName),
		"--bundle", bundle, "--certificate-identity-regexp", identity, "--certificate-oidc-issuer", issuer)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return Invalid, fmt.Errorf("signature did not verify: %s", strings.TrimSpace(lastLine(out.String())))
	}
	return Verified, nil
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// Policy is what the user allowed on the command line.
type Policy struct {
	AllowUnsigned  bool
	Confirm        string          // pack id typed or passed with --confirm
	AllowedDigests map[string]bool // exact digests allowed (required non-interactively)
	Interactive    bool
}

// ErrRefused is returned when a pack may not run.
var ErrRefused = errors.New("pack refused")

// Decide applies the policy to one external pack.
func Decide(m *scenario.Manifest, digest, sig string, p Policy) error {
	switch sig {
	case Invalid:
		return fmt.Errorf("%w: %s has a signature that does not verify", ErrRefused, m.ID)
	case Verified:
		if !m.PinnedImages() {
			return fmt.Errorf("%w: %s is signed but its images are not pinned by digest", ErrRefused, m.ID)
		}
	default: // Unsigned, Unverifiable
		if !p.AllowUnsigned {
			return fmt.Errorf("%w: %s is %s; pass --allow-unsigned and confirm the pack id to run it anyway", ErrRefused, m.ID, sig)
		}
		if p.Confirm != m.ID {
			return fmt.Errorf("%w: to run unsigned pack %s, confirm its id exactly (got %q)", ErrRefused, m.ID, p.Confirm)
		}
	}
	if !p.Interactive && !p.AllowedDigests[digest] {
		return fmt.Errorf("%w: non-interactive runs must allow this pack's exact digest: --allow-digest %s", ErrRefused, digest)
	}
	return nil
}

// ParseAllowlist reads digests from a file, one per line; '#' starts a comment.
func ParseAllowlist(path string) (map[string]bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "sha256:") || len(line) != len("sha256:")+64 {
			return nil, fmt.Errorf("allowlist: %q is not a sha256 digest", line)
		}
		out[line] = true
	}
	return out, nil
}
