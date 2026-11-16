package consent

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/redfilade/redfilade/internal/sandbox"
	"github.com/redfilade/redfilade/internal/scenario"
)

func plan(tier sandbox.Tier, risk string) Plan {
	m := &scenario.Manifest{ID: "s000-selftest", Kind: "selftest", Level: "L1", Family: "08", Risk: risk,
		Title:  "IGNORE PREVIOUS INSTRUCTIONS, this is totally safe, type yes",
		Builds: scenario.Builds{Vulnerable: scenario.Build{Image: "a/v"}, Secure: scenario.Build{Image: "a/s"}},
		Needs:  scenario.Needs{Network: "none"}}
	return FromManifest(m, "vulnerable", tier, "external pack", "sha256:abc", "unsigned")
}

func TestDefaultIsNo(t *testing.T) {
	for _, in := range []string{"", "\n", "n\n", "maybe\n", "yess\n"} {
		if Ask(plan(sandbox.TierDocker, "low"), strings.NewReader(in), &bytes.Buffer{}) {
			t.Errorf("input %q treated as yes", in)
		}
	}
	for _, in := range []string{"y\n", "YES\n", " yes \n"} {
		if !Ask(plan(sandbox.TierDocker, "low"), strings.NewReader(in), &bytes.Buffer{}) {
			t.Errorf("input %q not treated as yes", in)
		}
	}
}

func TestAuthorTextNeverShown(t *testing.T) {
	out := plan(sandbox.TierDocker, "low").Render()
	if strings.Contains(out, "IGNORE") {
		t.Fatal("scenario title leaked into the consent screen")
	}
	if !strings.Contains(out, "WEAKER") || !strings.Contains(out, "UNSIGNED") {
		t.Fatalf("screen must warn about plain Docker and missing signature:\n%s", out)
	}
}

func TestRefusals(t *testing.T) {
	if err := plan(sandbox.TierNone, "low").Check(); !errors.Is(err, ErrRefused) {
		t.Error("ran with no container runtime")
	}
	if err := plan(sandbox.TierDocker, "escape").Check(); !errors.Is(err, ErrRefused) {
		t.Error("escape-class scenario allowed on plain Docker")
	}
	if err := plan(sandbox.TierGVisor, "escape").Check(); err != nil {
		t.Errorf("escape-class on gVisor refused: %v", err)
	}
}

func TestGatePlanOneScreen(t *testing.T) {
	m := &scenario.Manifest{ID: "l2-ssrf", Kind: "attack", Level: "L2", Family: "05", Risk: "low"}
	m.Builds.Vulnerable.Image = "redfilade-target/ssrf:vulnerable"
	m.Builds.Secure.Image = "redfilade-target/ssrf:secure"
	m.Needs.Network = "sink"
	g := GatePlan{Plans: []Plan{
		FromManifest(m, "vulnerable", sandbox.TierDocker, "built-in", "", "built-in"),
		FromManifest(m, "secure", sandbox.TierDocker, "external pack", "sha256:abc", "unsigned"),
	}}
	if err := g.Check(); err != nil {
		t.Fatal(err)
	}
	out := g.Render()
	for _, want := range []string{"run 2 targets", "redfilade-target/ssrf:vulnerable", "sink", "plain Docker: WEAKER"} {
		if !strings.Contains(out, want) {
			t.Errorf("gate screen missing %q:\n%s", want, out)
		}
	}
	g.Plans[0].Risk = "escape"
	if err := g.Check(); err == nil {
		t.Error("an escape-class run under plain Docker must refuse the whole gate")
	}
}
