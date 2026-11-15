// Package triage turns evidence from an untrusted triage run into a short
// Markdown summary for maintainers.
//
// The evidence was produced while running contributor-supplied scenarios, so
// every field is hostile. The summary therefore prints only values that pass a
// strict allow-list: scenario ids matching the manifest id pattern, verdicts
// and builds from fixed sets, fact names known to the oracle, and counts.
// Anything else is replaced by a fixed placeholder. No excerpt, path, error,
// frame or free text from the evidence is ever printed.
package triage

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/redfilade/redfilade/internal/scenario"
)

// MaxFileBytes bounds how much of one evidence file is read.
const MaxFileBytes = 8 << 20

// MaxFiles bounds how many evidence files are summarized.
const MaxFiles = 64

var (
	reID       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,63}$`)
	verdicts   = map[string]bool{"exploited": true, "not_exploited": true, "inconclusive": true}
	builds     = map[string]bool{"vulnerable": true, "secure": true}
	reEvidence = regexp.MustCompile(`^evidence-[a-z0-9-]{3,64}-(vulnerable|secure)\.json$`)
)

// Row is one sanitized line of the summary.
type Row struct {
	ScenarioID string
	Build      string
	Verdict    string
	Facts      []string
	Unknown    int // findings whose fact name was not recognised
}

// evidence is the subset of report.Evidence the summary reads.
type evidence struct {
	Subject struct {
		ScenarioID string `json:"scenario_id"`
		Build      string `json:"build"`
	} `json:"subject"`
	Oracle struct {
		Verdict  string `json:"verdict"`
		Findings []struct {
			Fact string `json:"fact"`
		} `json:"findings"`
	} `json:"oracle"`
}

func pick(v string, ok bool) string {
	if ok {
		return v
	}
	return "(unrecognised)"
}

// Load reads evidence files from dir. Files whose names do not match the
// evidence pattern, symlinks and oversized files are skipped and counted.
func Load(dir string) (rows []Row, skipped int, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || !reEvidence.MatchString(e.Name()) {
			if e.Name() != "" && strings.HasPrefix(e.Name(), "evidence-") {
				skipped++
			}
			continue
		}
		if len(rows) >= MaxFiles {
			skipped++
			continue
		}
		r, ok := readOne(filepath.Join(dir, e.Name()))
		if !ok {
			skipped++
			continue
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].ScenarioID != rows[j].ScenarioID {
			return rows[i].ScenarioID < rows[j].ScenarioID
		}
		return rows[i].Build > rows[j].Build // vulnerable before secure
	})
	return rows, skipped, nil
}

func readOne(path string) (Row, bool) {
	f, err := os.Open(path)
	if err != nil {
		return Row{}, false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil || len(b) > MaxFileBytes {
		return Row{}, false
	}
	var ev evidence
	if err := json.Unmarshal(b, &ev); err != nil {
		return Row{}, false
	}
	r := Row{
		ScenarioID: pick(ev.Subject.ScenarioID, reID.MatchString(ev.Subject.ScenarioID)),
		Build:      pick(ev.Subject.Build, builds[ev.Subject.Build]),
		Verdict:    pick(ev.Oracle.Verdict, verdicts[ev.Oracle.Verdict]),
	}
	seen := map[string]bool{}
	for _, f := range ev.Oracle.Findings {
		if !scenario.Facts[f.Fact] {
			r.Unknown++
			continue
		}
		if !seen[f.Fact] {
			seen[f.Fact] = true
			r.Facts = append(r.Facts, f.Fact)
		}
	}
	sort.Strings(r.Facts)
	return r, true
}

// Expectation states whether a row behaved as a Range twin should.
func Expectation(r Row) string {
	switch {
	case r.Build == "vulnerable" && r.Verdict == "exploited":
		return "as expected"
	case r.Build == "secure" && r.Verdict == "not_exploited":
		return "as expected"
	default:
		return "NEEDS REVIEW"
	}
}

// Markdown writes the summary. Every printed value has passed an allow-list,
// and none of them can contain Markdown or HTML syntax.
func Markdown(w io.Writer, rows []Row, skipped int) error {
	var b strings.Builder
	b.WriteString("## Redfilade triage\n\n")
	b.WriteString("Contributor-supplied scenarios were run as data in isolated cells. ")
	b.WriteString("This summary lists only checked ids, verdicts and fact names; read the evidence artifact for details.\n\n")
	if len(rows) == 0 {
		b.WriteString("No evidence was produced.\n")
	} else {
		b.WriteString("| Scenario | Build | Verdict | Facts | Result |\n|---|---|---|---|---|\n")
		for _, r := range rows {
			facts := "none"
			if len(r.Facts) > 0 {
				facts = strings.Join(r.Facts, ", ")
			}
			if r.Unknown > 0 {
				facts += fmt.Sprintf(" (+%d unrecognised)", r.Unknown)
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n", r.ScenarioID, r.Build, r.Verdict, facts, Expectation(r))
		}
	}
	if skipped > 0 {
		fmt.Fprintf(&b, "\n%d file(s) were skipped (unexpected name, size or format).\n", skipped)
	}
	_, err := io.WriteString(w, b.String())
	return err
}
