// Package scenario loads and validates scenario manifests (ADR-0013).
//
// A manifest is untrusted input: it is size-capped, decoded strictly with
// unknown fields rejected, and every field is bounded before anything else
// in the CLI looks at it.
package scenario

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// SchemaV1 identifies the manifest format.
const SchemaV1 = "redfilade.scenario/v1"

// FileName is the manifest's name inside a scenario directory.
const FileName = "scenario.json"

// Limits on untrusted manifests.
const (
	MaxManifestBytes = 256 << 10
	MaxWorldFiles    = 64
	MaxWorldBytes    = 64 << 10
	MaxSteps         = 64
	MaxChecks        = 32
	MaxTitle         = 120
	MaxSummary       = 600
)

var (
	reID      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,63}$`)
	reFamily  = regexp.MustCompile(`^(0[1-9]|1[0-9]|2[0-6])$`)
	reLevel   = regexp.MustCompile(`^L[1-5]$`)
	reImage   = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,200}(:[A-Za-z0-9._-]{1,128})?(@sha256:[a-f0-9]{64})?$`)
	reCanary  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,31}$`)
	reTool    = regexp.MustCompile(`^[A-Za-z0-9_.\-/]{1,128}$`)
	reBattery = regexp.MustCompile(`^l[1-5]-[a-z0-9-]{2,48}$`)
	reEnvName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
)

// Manifest is a validated scenario.
type Manifest struct {
	Schema   string   `json:"schema"`
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Summary  string   `json:"summary"`
	Family   string   `json:"family"`
	Level    string   `json:"level"`
	Protocol string   `json:"protocol"`
	Risk     string   `json:"risk"`
	Kind     string   `json:"kind"`
	Credits  []string `json:"credits,omitempty"`
	Builds   Builds   `json:"builds"`
	Needs    Needs    `json:"needs"`
	World    []File   `json:"world,omitempty"`
	Exploit  []Step   `json:"exploit,omitempty"`
	Agent    *Agent   `json:"agent,omitempty"` // kind "agent" (L3) only
	Oracle   Oracle   `json:"oracle"`

	// Dir is where the manifest was loaded from (not part of the JSON).
	Dir string `json:"-"`
	// Raw holds the exact manifest bytes, used for the pack digest.
	Raw []byte `json:"-"`
}

// Agent describes an L3 scenario: a model works on an ordinary task with the
// target's tools while the attack arrives through tool data.
type Agent struct {
	Task     string `json:"task"`      // what the user asks the agent to do
	Trials   int    `json:"trials"`    // independent runs, each in a fresh cell
	MaxSteps int    `json:"max_steps"` // model turns per trial
}

// Builds holds the vulnerable and secure twins.
type Builds struct {
	Vulnerable Build `json:"vulnerable"`
	Secure     Build `json:"secure"`
}

// Build is one twin: an image, optionally built from a context directory.
type Build struct {
	Image   string   `json:"image"`
	Context string   `json:"context,omitempty"`
	Cmd     []string `json:"cmd,omitempty"`
}

// Needs declares what the cell may use. Anything not declared is denied.
type Needs struct {
	Network string   `json:"network"`       // "none" or "sink"
	Env     []EnvVar `json:"env,omitempty"` // variables passed into the cell
}

// EnvVar is a variable passed into the cell; its value may use {{canary.X}}.
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// File is a world file seeded into the synthetic organisation.
type File struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// Step is one exploit action: an MCP call or a built-in battery attack.
type Step struct {
	Call      string         `json:"call,omitempty"` // tool name for tools/call
	Arguments map[string]any `json:"arguments,omitempty"`
	Battery   string         `json:"battery,omitempty"` // e.g. "l1-leaky-errors"
}

// Oracle lists the facts that prove the exploit worked.
type Oracle struct {
	Match  string  `json:"match"` // "any" (default) or "all"
	Checks []Check `json:"checks"`
}

// Check is one observable fact.
type Check struct {
	Fact   string `json:"fact"`             // see Facts
	Canary string `json:"canary,omitempty"` // for canary_leaked
	Path   string `json:"path,omitempty"`   // for world_file_changed
}

// Facts the oracle can observe.
var Facts = map[string]bool{
	"canary_leaked":         true, // a canary value crossed from the target to the client
	"world_file_changed":    true, // a world file's content changed during the run
	"internals_leaked":      true, // stack traces, source paths or runtime internals in replies
	"secret_pattern_leaked": true, // well-known credential formats in replies
	"sensitive_file_read":   true, // contents of system files (passwd, private keys, environ) in replies
	"egress_reached_sink":   true, // the target made a network request (needs network "sink")
	"canary_egressed":       true, // a canary was sent out to the sink (exfiltration)
	// Rule-based facts (internal/rules, Cisco MCP Scanner rules).
	"tool_metadata_flagged":    true, // a tool description or parameter text matches a detection rule
	"output_injection_flagged": true, // tool output carries prompt-injection, coercion or hidden-script text
	// HTTP facts (targets reached over Streamable HTTP).
	"auth_bypassed":            true, // a request with a missing, malformed, forged or wrong-audience token got a result
	"rate_limit_missing":       true, // a burst of requests was all served, with no 429 or 503
	"header_mismatch_accepted": true, // a request whose Mcp-Method or Mcp-Name header disagrees with its body got a result
	// Agent facts (L3).
	"agent_leaked_canary": true, // the agent sent a canary in a tool call the server carried out
}

// SinkCanary is planted automatically in every scenario that uses the sink;
// the sink includes it in every response.
const SinkCanary = "SINK"

// Load reads and validates dir/scenario.json.
func Load(dir string) (*Manifest, error) {
	f, err := os.Open(filepath.Join(dir, FileName))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir, FileName), err)
	}
	m.Dir = dir
	if err := m.checkContexts(); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir, FileName), err)
	}
	return m, nil
}

// Parse decodes and validates a manifest from r.
func Parse(r io.Reader) (*Manifest, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxManifestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest larger than %d bytes", MaxManifestBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if dec.More() {
		return nil, errors.New("trailing data after manifest")
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	m.Raw = b
	return &m, nil
}

// LoadFS reads and validates dir/scenario.json from an fs.FS (used for the
// scenarios built into the binary).
func LoadFS(fsys fs.FS, dir string) (*Manifest, error) {
	f, err := fsys.Open(path.Join(dir, FileName))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path.Join(dir, FileName), err)
	}
	return m, nil
}

// PinnedImages reports whether both builds reference images by digest.
func (m *Manifest) PinnedImages() bool {
	return strings.Contains(m.Builds.Vulnerable.Image, "@sha256:") && strings.Contains(m.Builds.Secure.Image, "@sha256:")
}

// Validate checks every field against the format's bounds.
func (m *Manifest) Validate() error {
	var errs []string
	bad := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }

	if m.Schema != SchemaV1 {
		bad("schema must be %q", SchemaV1)
	}
	if !reID.MatchString(m.ID) {
		bad("id must match %s", reID)
	}
	if m.Title == "" || len(m.Title) > MaxTitle || hasControl(m.Title) {
		bad("title must be 1-%d printable characters", MaxTitle)
	}
	if len(m.Summary) > MaxSummary || hasControl(m.Summary) {
		bad("summary must be at most %d printable characters", MaxSummary)
	}
	if !reFamily.MatchString(m.Family) {
		bad("family must be a register family 01-26")
	}
	if !reLevel.MatchString(m.Level) {
		bad("level must be L1-L5")
	}
	if m.Protocol != "2026-07-28" && m.Protocol != "2025-11-25" {
		bad("protocol must be 2026-07-28 or 2025-11-25")
	}
	if m.Risk != "low" && m.Risk != "escape" {
		bad(`risk must be "low" or "escape"`)
	}
	if m.Kind != "attack" && m.Kind != "selftest" && m.Kind != "agent" {
		bad(`kind must be "attack", "selftest" or "agent"`)
	}
	if m.Kind == "agent" {
		switch {
		case m.Agent == nil:
			bad("agent scenarios need an agent block")
		case m.Level != "L3":
			bad("agent scenarios are level L3")
		case len(m.Agent.Task) == 0 || len(m.Agent.Task) > 500 || hasControl(m.Agent.Task):
			bad("agent.task must be 1-500 printable characters")
		case m.Agent.Trials < 1 || m.Agent.Trials > 50:
			bad("agent.trials must be 1-50")
		case m.Agent.MaxSteps < 1 || m.Agent.MaxSteps > 20:
			bad("agent.max_steps must be 1-20")
		}
		if len(m.Exploit) != 0 {
			bad("agent scenarios have no exploit steps: the agent acts")
		}
	} else if m.Agent != nil {
		bad("only agent scenarios have an agent block")
	}
	if len(m.Credits) > 8 {
		bad("at most 8 credits")
	}
	for _, c := range m.Credits {
		if len(c) > 200 || hasControl(c) {
			bad("credit entries must be at most 200 printable characters")
		}
	}
	for name, b := range map[string]Build{"vulnerable": m.Builds.Vulnerable, "secure": m.Builds.Secure} {
		if !reImage.MatchString(b.Image) {
			bad("builds.%s.image is not a valid image reference", name)
		}
		if b.Context != "" && !safeRel(b.Context) {
			bad("builds.%s.context must be a relative path inside the scenario", name)
		}
		if len(b.Cmd) > 16 {
			bad("builds.%s.cmd has too many arguments", name)
		}
		for _, a := range b.Cmd {
			if len(a) > 256 || hasControl(a) {
				bad("builds.%s.cmd arguments must be short and printable", name)
			}
		}
	}
	if m.Builds.Vulnerable.Image == m.Builds.Secure.Image && m.Builds.Vulnerable.Image != "" &&
		strings.Join(m.Builds.Vulnerable.Cmd, " ") == strings.Join(m.Builds.Secure.Cmd, " ") {
		bad("vulnerable and secure builds must differ")
	}
	if m.Needs.Network != "none" && m.Needs.Network != "sink" {
		bad(`needs.network must be "none" or "sink"`)
	}
	if len(m.Needs.Env) > 16 {
		bad("needs.env allows at most 16 variables")
	}
	for _, e := range m.Needs.Env {
		if !reEnvName.MatchString(e.Name) || len(e.Value) > 512 || hasControl(e.Value) {
			bad("needs.env entries need an UPPER_CASE name and a short printable value")
		}
		if err := checkPlaceholders(e.Value); err != nil {
			bad("needs.env %s: %v", e.Name, err)
		}
	}
	if len(m.World) > MaxWorldFiles {
		bad("world allows at most %d files", MaxWorldFiles)
	}
	seen := map[string]bool{}
	for _, f := range m.World {
		if !safeRel(f.Path) {
			bad("world path %q must be relative and stay inside the world", f.Path)
		}
		if seen[f.Path] {
			bad("world path %q is duplicated", f.Path)
		}
		seen[f.Path] = true
		if len(f.Content) > MaxWorldBytes {
			bad("world file %q is larger than %d bytes", f.Path, MaxWorldBytes)
		}
		if err := checkPlaceholders(f.Content); err != nil {
			bad("world file %q: %v", f.Path, err)
		}
	}
	if (m.Kind != "agent" && len(m.Exploit) == 0) || len(m.Exploit) > MaxSteps {
		bad("exploit needs 1-%d steps", MaxSteps)
	}
	for i, s := range m.Exploit {
		switch {
		case s.Call != "" && s.Battery != "":
			bad("exploit step %d sets both call and battery", i+1)
		case s.Call != "":
			if !reTool.MatchString(s.Call) {
				bad("exploit step %d: invalid tool name", i+1)
			}
			if len(s.Arguments) > 32 {
				bad("exploit step %d: too many arguments", i+1)
			}
		case s.Battery != "":
			if !reBattery.MatchString(s.Battery) {
				bad("exploit step %d: invalid battery attack id", i+1)
			}
			if len(s.Arguments) != 0 {
				bad("exploit step %d: battery steps take no arguments", i+1)
			}
		default:
			bad("exploit step %d needs call or battery", i+1)
		}
	}
	if m.Oracle.Match == "" {
		m.Oracle.Match = "any"
	}
	if m.Oracle.Match != "any" && m.Oracle.Match != "all" {
		bad(`oracle.match must be "any" or "all"`)
	}
	if len(m.Oracle.Checks) == 0 || len(m.Oracle.Checks) > MaxChecks {
		bad("oracle needs 1-%d checks", MaxChecks)
	}
	canaries := m.Canaries()
	for i, c := range m.Oracle.Checks {
		if !Facts[c.Fact] {
			bad("oracle check %d: unknown fact %q", i+1, c.Fact)
			continue
		}
		switch c.Fact {
		case "canary_leaked", "canary_egressed", "agent_leaked_canary":
			if !canaries[c.Canary] {
				bad("oracle check %d: canary %q is not planted in the world or env", i+1, c.Canary)
			}
		case "egress_reached_sink":
			if m.Needs.Network != "sink" {
				bad("oracle check %d: egress_reached_sink needs needs.network \"sink\"", i+1)
			}
		case "world_file_changed":
			if !seen[c.Path] {
				bad("oracle check %d: %q is not a world file", i+1, c.Path)
			}
		}
	}
	if len(errs) > 0 {
		return errors.New("invalid scenario: " + strings.Join(errs, "; "))
	}
	return nil
}

func (m *Manifest) checkContexts() error {
	for name, b := range map[string]Build{"vulnerable": m.Builds.Vulnerable, "secure": m.Builds.Secure} {
		if b.Context == "" {
			continue
		}
		st, err := os.Stat(filepath.Join(m.Dir, filepath.FromSlash(b.Context)))
		if err != nil || !st.IsDir() {
			return fmt.Errorf("builds.%s.context %q is not a directory", name, b.Context)
		}
	}
	return nil
}

var rePlaceholder = regexp.MustCompile(`\{\{\s*([^}]*)\s*\}\}`)

// checkPlaceholders allows only {{canary.NAME}} placeholders.
func checkPlaceholders(s string) error {
	for _, m := range rePlaceholder.FindAllStringSubmatch(s, -1) {
		inner := strings.TrimSpace(m[1])
		name, ok := strings.CutPrefix(inner, "canary.")
		if !ok || !reCanary.MatchString(name) {
			return fmt.Errorf("unsupported placeholder %q (only {{canary.NAME}})", m[0])
		}
	}
	return nil
}

// Canaries returns every canary name the manifest plants.
func (m *Manifest) Canaries() map[string]bool {
	out := map[string]bool{}
	add := func(s string) {
		for _, x := range rePlaceholder.FindAllStringSubmatch(s, -1) {
			if name, ok := strings.CutPrefix(strings.TrimSpace(x[1]), "canary."); ok {
				out[name] = true
			}
		}
	}
	for _, f := range m.World {
		add(f.Content)
	}
	for _, e := range m.Needs.Env {
		add(e.Value)
	}
	if m.Needs.Network == "sink" {
		out[SinkCanary] = true
	}
	return out
}

// Render replaces {{canary.NAME}} placeholders with this run's values.
func Render(s string, canaries map[string]string) string {
	return rePlaceholder.ReplaceAllStringFunc(s, func(p string) string {
		inner := strings.TrimSpace(rePlaceholder.FindStringSubmatch(p)[1])
		if name, ok := strings.CutPrefix(inner, "canary."); ok {
			if v, ok := canaries[name]; ok {
				return v
			}
		}
		return p
	})
}

func safeRel(p string) bool {
	if p == "" || len(p) > 200 || strings.ContainsAny(p, "\\:\x00") || path.IsAbs(p) {
		return false
	}
	c := path.Clean(p)
	return c == p && c != "." && !strings.HasPrefix(c, "../") && c != ".."
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 && r != '\n' && r != '\t' || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x202e || r == 0x202d || (r >= 0x2066 && r <= 0x2069) {
			return true
		}
	}
	return false
}
