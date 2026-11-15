// Package battery holds Redfilade's built-in attacks.
//
// Built-in attacks are trusted code shipped with the CLI. They only send MCP
// requests; they never judge results themselves. The oracle decides what
// happened from the recorded frames (ADR-0013).
package battery

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/redfilade/redfilade/internal/mcp"
	"github.com/redfilade/redfilade/internal/scenario"
)

// Attack is a built-in battery attack.
type Attack struct {
	ID     string
	Level  string
	Family string
	Title  string
	// Checks are the oracle facts this attack is judged by when it runs
	// against a builder's own server (no scenario manifest).
	Checks []scenario.Check
	// World files and env a builder-mode run plants for this attack.
	World []scenario.File
	Env   []scenario.EnvVar
	// Network the attack needs in builder mode: "none" or "sink".
	Network string
	Run     func(ctx context.Context, c *mcp.Client, tools []mcp.Tool, env Env) error
}

// Env is what an attack may know about the run.
type Env struct {
	Canaries map[string]string // planted canary values by name
	SinkURL  string            // base URL of the egress sink, "" without a sink
}

var registry = map[string]Attack{}

func register(a Attack) { registry[a.ID] = a }

// Get returns a built-in attack by id.
func Get(id string) (Attack, bool) {
	a, ok := registry[id]
	return a, ok
}

// ForLevel returns the attacks that make up a level's battery, in order.
// Levels are cumulative: L2 includes L1.
func ForLevel(level string) []Attack {
	var out []Attack
	for _, a := range registry {
		if a.Level <= level && len(a.Level) == len(level) {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// IDs lists every registered attack.
func IDs() []string {
	var out []string
	for id := range registry {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// maxToolsProbed bounds the work done against servers with many tools.
const maxToolsProbed = 25

func init() {
	register(Attack{
		ID:      "l1-leaky-errors",
		Level:   "L1",
		Family:  "08",
		Title:   "Error messages leak internals or secrets",
		Checks:  []scenario.Check{{Fact: "internals_leaked"}},
		Network: "none",
		Run:     leakyErrors,
	})
}

// leakyErrors sends malformed input to every tool and to an unknown tool,
// then lets the oracle inspect the error replies.
func leakyErrors(ctx context.Context, c *mcp.Client, tools []mcp.Tool, _ Env) error {
	if _, err := c.CallTool(ctx, "redfilade_probe_nonexistent_tool", map[string]any{}); err != nil {
		return fmt.Errorf("unknown-tool probe: %w", err)
	}
	if len(tools) > maxToolsProbed {
		tools = tools[:maxToolsProbed]
	}
	for _, t := range tools {
		for _, args := range malformed(t.InputSchema) {
			if _, err := c.CallTool(ctx, t.Name, args); err != nil {
				return fmt.Errorf("probe %q: %w", t.Name, err)
			}
		}
	}
	return nil
}

// malformed builds a small, fixed set of invalid argument objects from a
// tool's input schema. The values are harmless: wrong types, missing fields,
// unexpected structure and a bounded long string. Nothing is executable.
func malformed(schema json.RawMessage) []map[string]any {
	var s struct {
		Properties map[string]struct {
			Type any `json:"type"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	_ = json.Unmarshal(schema, &s)

	names := make([]string, 0, len(s.Properties))
	for n := range s.Properties {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) > 8 {
		names = names[:8]
	}

	cases := []map[string]any{
		{}, // every required field missing
		{"__redfilade_unexpected__": map[string]any{"nested": []any{1, "two", nil}}},
	}
	wrong := map[string]any{}
	long := map[string]any{}
	for _, n := range names {
		wrong[n] = wrongTypeFor(s.Properties[n].Type)
		long[n] = strings.Repeat("A", 8192)
	}
	if len(names) > 0 {
		cases = append(cases, wrong, long)
	}
	return cases
}

func wrongTypeFor(t any) any {
	switch fmt.Sprint(t) {
	case "string":
		return map[string]any{"not": "a string"}
	case "integer", "number":
		return "not-a-number"
	case "boolean":
		return []any{"not", "a", "boolean"}
	case "array":
		return 12345
	case "object":
		return "not-an-object"
	default:
		return []any{nil, map[string]any{}}
	}
}
