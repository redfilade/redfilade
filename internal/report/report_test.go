package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/redfilade/redfilade/internal/mcp"
	"github.com/redfilade/redfilade/internal/oracle"
)

func evidence(verdict string, excerpt string) *Evidence {
	return &Evidence{Schema: SchemaEvidence, Subject: Subject{Mode: "test", Image: "x/y:z", Level: "L1"},
		Oracle:    oracle.Result{Verdict: verdict, Findings: []oracle.Finding{{Fact: "internals_leaked", Detector: "go-panic", Excerpt: excerpt}}},
		Signature: Unsigned}
}

func TestCleanStripsHostileCharacters(t *testing.T) {
	in := "ok\x1b[31mRED‮evil⁦x​z\x00\n" + strings.Repeat("A", 1000)
	out := Clean(in, 50)
	for _, bad := range []string{"\x1b", "‮", "⁦", "​", "\x00", "\n"} {
		if strings.Contains(out, bad) {
			t.Errorf("Clean kept %q", bad)
		}
	}
	if len([]rune(out)) > 51 {
		t.Errorf("not truncated: %d runes", len([]rune(out)))
	}
}

func TestSARIFEscapesAndUsesOurRuleText(t *testing.T) {
	var b bytes.Buffer
	if err := WriteSARIF(&b, evidence(oracle.Exploited, `<img src=x onerror=alert(1)> ](javascript:alert(1))`), "0.0.1", "server/main.go"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "<img") {
		t.Fatal("raw HTML reached SARIF output")
	}
	var log map[string]any
	if err := json.Unmarshal(b.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	run := log["runs"].([]any)[0].(map[string]any)
	rule := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if rule["id"] != "RF-INTERNALS-LEAK" {
		t.Fatalf("rule id = %v", rule["id"])
	}
	if log["version"] != "2.1.0" {
		t.Fatal("not SARIF 2.1.0")
	}
}

func TestJUnitExpectations(t *testing.T) {
	var b bytes.Buffer
	cases := []Case{
		{Name: "vulnerable twin", Evidence: evidence(oracle.Exploited, "x"), WantExploited: true},
		{Name: "secure twin", Evidence: evidence(oracle.Exploited, "]]><script>"), WantExploited: false},
		{Name: "crashed", Evidence: evidence(oracle.Inconclusive, ""), WantExploited: false},
	}
	if err := WriteJUnit(&b, "gate", cases); err != nil {
		t.Fatal(err)
	}
	var doc junitSuites
	if err := xml.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatalf("invalid XML: %v\n%s", err, b.String())
	}
	s := doc.Suites[0]
	if s.Tests != 3 || s.Failures != 1 || s.Errors != 1 {
		t.Fatalf("tests=%d failures=%d errors=%d", s.Tests, s.Failures, s.Errors)
	}
	if strings.Contains(b.String(), "<script>") {
		t.Fatal("unescaped markup in JUnit")
	}
}

func TestRedactFrames(t *testing.T) {
	fr := []mcp.Frame{{Seq: 1, Raw: json.RawMessage(`{"t":"CANARY_DB_XYZ"}`)}}
	out := RedactFrames(fr, map[string]string{"DB": "CANARY_DB_XYZ"})
	if strings.Contains(string(out[0].Raw), "CANARY_DB_XYZ") || !json.Valid(out[0].Raw) {
		t.Fatalf("redaction failed: %s", out[0].Raw)
	}
}
