// Package consent shows what a run will do and asks before doing it
// (ADR-0015, architecture record 10.4).
//
// The screen is built only from validated, structured manifest fields. Free
// text written by the scenario author (title, summary) is never shown here,
// so a malicious scenario cannot write its own reassuring message.
package consent

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/redfilade/redfilade/internal/sandbox"
	"github.com/redfilade/redfilade/internal/scenario"
)

// Plan is everything the user is agreeing to.
type Plan struct {
	ScenarioID string
	Kind       string
	Level      string
	Family     string
	Risk       string
	Build      string // "vulnerable", "secure" or "target"
	Image      string
	Network    string
	WorldFiles []string
	EnvNames   []string
	Tier       sandbox.Tier
	Signed     bool
}

// ErrRefused means the plan is not allowed on this machine at all.
var ErrRefused = errors.New("refused")

// FromManifest builds a plan for one build of a scenario.
func FromManifest(m *scenario.Manifest, build string, tier sandbox.Tier, signed bool) Plan {
	b := m.Builds.Secure
	if build == "vulnerable" {
		b = m.Builds.Vulnerable
	}
	p := Plan{ScenarioID: m.ID, Kind: m.Kind, Level: m.Level, Family: m.Family, Risk: m.Risk,
		Build: build, Image: b.Image, Network: m.Needs.Network, Tier: tier, Signed: signed}
	for _, f := range m.World {
		p.WorldFiles = append(p.WorldFiles, f.Path)
	}
	for _, e := range m.Needs.Env {
		p.EnvNames = append(p.EnvNames, e.Name)
	}
	sort.Strings(p.WorldFiles)
	sort.Strings(p.EnvNames)
	return p
}

// Check refuses plans that must never run here.
func (p Plan) Check() error {
	switch p.Tier {
	case sandbox.TierNone:
		return fmt.Errorf("%w: no container runtime found; Redfilade never runs targets directly on your machine", ErrRefused)
	case sandbox.TierDocker:
		if p.Risk == "escape" {
			return fmt.Errorf("%w: %s is an escape-class scenario and needs gVisor or a microVM, not plain Docker", ErrRefused, p.ScenarioID)
		}
	}
	return nil
}

// Render returns the consent screen.
func (p Plan) Render() string {
	var b strings.Builder
	line := func(k, v string) { fmt.Fprintf(&b, "  %-12s %s\n", k, v) }
	b.WriteString("Redfilade is about to run a target in an isolated cell.\n\n")
	line("Scenario", fmt.Sprintf("%s (%s, %s, family %s)", p.ScenarioID, p.Kind, p.Level, p.Family))
	line("Build", p.Build)
	line("Image", p.Image)
	net := "none (no network at all)"
	if p.Network == "sink" {
		net = "internal sink only (no internet)"
	}
	line("Network", net)
	if len(p.WorldFiles) == 0 {
		line("World files", "none")
	} else {
		line("World files", strings.Join(p.WorldFiles, ", "))
	}
	if len(p.EnvNames) == 0 {
		line("Env vars", "none")
	} else {
		line("Env vars", strings.Join(p.EnvNames, ", "))
	}
	switch p.Tier {
	case sandbox.TierGVisor:
		line("Isolation", "gVisor (separate kernel boundary)")
	case sandbox.TierDocker:
		line("Isolation", "plain Docker: WEAKER, shares your kernel")
	default:
		line("Isolation", "none available")
	}
	risk := "low"
	if p.Risk == "escape" {
		risk = "ESCAPE-CLASS: tries to break out of isolation"
	}
	line("Risk", risk)
	if p.Signed {
		line("Signature", "verified")
	} else {
		line("Signature", "UNSIGNED")
	}
	b.WriteString("\n  The cell gets no home folder, no SSH or cloud keys, no Docker socket\n  and none of your environment variables.\n")
	return b.String()
}

// Ask prints the screen and returns true only for an explicit "y" or "yes".
// Anything else, including an empty line or end of input, is No.
func Ask(p Plan, in io.Reader, out io.Writer) bool {
	fmt.Fprint(out, p.Render())
	fmt.Fprint(out, "\nRun it? [y/N] ")
	line, _ := bufio.NewReader(io.LimitReader(in, 64)).ReadString('\n')
	ans := strings.ToLower(strings.TrimSpace(line))
	return ans == "y" || ans == "yes"
}
