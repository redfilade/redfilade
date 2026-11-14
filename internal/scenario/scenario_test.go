package scenario

import (
	"strings"
	"testing"
)

const valid = `{
  "schema": "redfilade.scenario/v1",
  "id": "s000-selftest",
  "title": "Harness self-test",
  "summary": "Checks the range plumbing.",
  "family": "08", "level": "L1", "protocol": "2026-07-28", "risk": "low", "kind": "selftest",
  "builds": {"vulnerable": {"image": "redfilade/selftest:vulnerable"}, "secure": {"image": "redfilade/selftest:secure"}},
  "needs": {"network": "none", "env": [{"name": "API_TOKEN", "value": "{{canary.TOKEN}}"}]},
  "world": [{"path": "config/app.env", "content": "DB_PASSWORD={{canary.DB}}\n"}],
  "exploit": [{"call": "echo", "arguments": {"text": "hi"}}, {"battery": "l1-leaky-errors"}],
  "oracle": {"checks": [{"fact": "canary_leaked", "canary": "DB"}, {"fact": "world_file_changed", "path": "config/app.env"}]}
}`

func TestValidManifest(t *testing.T) {
	m, err := Parse(strings.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	if m.Oracle.Match != "any" {
		t.Errorf("default match = %q, want any", m.Oracle.Match)
	}
	if c := m.Canaries(); !c["DB"] || !c["TOKEN"] || len(c) != 2 {
		t.Errorf("canaries = %v", c)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":      `"id": "s000-selftest", "hooks": ["rm -rf /"],`,
		"path traversal":     `"world": [{"path": "../../etc/passwd", "content": "x"}],`,
		"absolute path":      `"world": [{"path": "/etc/passwd", "content": "x"}],`,
		"bad placeholder":    `"world": [{"path": "a.txt", "content": "{{env.HOME}}"}],`,
		"unknown fact":       `"oracle": {"checks": [{"fact": "flag_captured"}]},`,
		"unplanted canary":   `"oracle": {"checks": [{"fact": "canary_leaked", "canary": "NOPE"}]},`,
		"host network":       `"needs": {"network": "host"},`,
		"bidi control title": "\"title\": \"safe‮evil\",",
		"same twins":         `"builds": {"vulnerable": {"image": "a/b:1"}, "secure": {"image": "a/b:1"}},`,
		"image option":       `"builds": {"vulnerable": {"image": "--privileged"}, "secure": {"image": "a/b:2"}},`,
	}
	for name, override := range cases {
		t.Run(name, func(t *testing.T) {
			doc := strings.Replace(valid, "{\n", "{\n"+override+"\n", 1)
			// Duplicate keys: Go keeps the last one, so put the override last instead.
			doc = strings.TrimSuffix(strings.TrimSpace(valid), "}") + "," + strings.TrimSuffix(strings.TrimSpace(override), ",") + "}"
			if _, err := Parse(strings.NewReader(doc)); err == nil {
				t.Fatalf("accepted: %s", override)
			}
		})
	}
}

func TestOversizedManifest(t *testing.T) {
	big := `{"schema":"` + strings.Repeat("x", MaxManifestBytes) + `"}`
	if _, err := Parse(strings.NewReader(big)); err == nil {
		t.Fatal("oversized manifest accepted")
	}
}

func TestRender(t *testing.T) {
	got := Render("a={{canary.DB}} b={{ canary.X }}", map[string]string{"DB": "CANARY_DB_1", "X": "CANARY_X_2"})
	if got != "a=CANARY_DB_1 b=CANARY_X_2" {
		t.Fatalf("render = %q", got)
	}
}
