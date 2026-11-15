package triage

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSummaryPrintsOnlyAllowListedValues(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "evidence-l2-new-thing-vulnerable.json", `{
	  "subject": {"scenario_id": "l2-new-thing", "build": "vulnerable"},
	  "oracle": {"verdict": "exploited", "findings": [
	    {"fact": "canary_leaked", "excerpt": "<img src=x onerror=alert(1)>"},
	    {"fact": "canary_leaked"},
	    {"fact": "<script>alert(1)</script>"}
	  ]}}`)
	write(t, dir, "evidence-l2-new-thing-secure.json", `{
	  "subject": {"scenario_id": "L2 | injected | row", "build": "secure<b>"},
	  "oracle": {"verdict": "</table>pwned", "findings": []}}`)
	write(t, dir, "evidence-bad name.json", `{}`)
	write(t, dir, "evidence-l2-x-vulnerable.json", `not json`)
	write(t, dir, "README.md", "ignored")

	rows, skipped, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || skipped != 2 {
		t.Fatalf("rows %d skipped %d", len(rows), skipped)
	}
	var out bytes.Buffer
	if err := Markdown(&out, rows, skipped); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, bad := range []string{"<", ">", "onerror", "injected", "pwned", "script"} {
		if strings.Contains(s, bad) {
			t.Errorf("summary leaked %q:\n%s", bad, s)
		}
	}
	for _, want := range []string{"`l2-new-thing` | vulnerable | exploited | canary_leaked (+1 unrecognised) | as expected", "(unrecognised)", "NEEDS REVIEW", "2 file(s) were skipped"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary missing %q:\n%s", want, s)
		}
	}
}

func TestOversizedFileIsSkipped(t *testing.T) {
	dir := t.TempDir()
	big := `{"subject":{"scenario_id":"l1-big","build":"secure"},"pad":"` + strings.Repeat("a", MaxFileBytes) + `"}`
	write(t, dir, "evidence-l1-big-secure.json", big)
	rows, skipped, err := Load(dir)
	if err != nil || len(rows) != 0 || skipped != 1 {
		t.Fatalf("rows %d skipped %d err %v", len(rows), skipped, err)
	}
}

func TestSymlinkIsSkipped(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "outside.json")
	write(t, filepath.Dir(target), "outside.json", `{"subject":{"scenario_id":"l1-out","build":"secure"},"oracle":{"verdict":"not_exploited"}}`)
	if err := os.Symlink(target, filepath.Join(dir, "evidence-l1-out-secure.json")); err != nil {
		t.Skip("symlinks unavailable")
	}
	rows, skipped, _ := Load(dir)
	if len(rows) != 0 || skipped != 1 {
		t.Fatalf("rows %d skipped %d", len(rows), skipped)
	}
}
