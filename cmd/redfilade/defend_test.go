package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/redfilade/redfilade/internal/sandbox"
)

// TestDefendEndToEnd measures both builds of the defence-rules twin: the
// strict build should stop the injection families without blocking any
// benign call, and the permissive build should stop nothing.
func TestDefendEndToEnd(t *testing.T) {
	shim := buildTwins(t)
	for _, mode := range []string{"secure", "vulnerable"} {
		out := t.TempDir()
		var stdout, stderr bytes.Buffer
		args := []string{"defend", "--yes", "--out", out, "--defence-image", "redfilade-target/defence-rules:" + mode,
			"--min-block-rate", "0.5", "--max-false-positive-rate", "0"}
		code := Main(context.Background(), args, strings.NewReader(""), &stdout, &stderr, sandbox.Runner{Binary: shim})
		b, err := os.ReadFile(filepath.Join(out, "defence-report.json"))
		if err != nil {
			t.Fatalf("%s: no report (exit %d)\n%s\n%s", mode, code, stdout.String(), stderr.String())
		}
		var rep defenceReport
		if err := json.Unmarshal(b, &rep); err != nil {
			t.Fatal(err)
		}
		if len(rep.Errors) > 0 {
			t.Errorf("%s: errors %v", mode, rep.Errors)
		}
		stopped := map[string]bool{}
		for _, a := range rep.Attacks {
			stopped[a.Scenario] = a.Stopped
		}
		switch mode {
		case "secure":
			if code != exitPass {
				t.Fatalf("strict defence: exit %d\n%s", code, stdout.String())
			}
			for _, id := range []string{"l2-path-traversal", "l2-sql-injection", "l2-command-injection", "l2-ssrf"} {
				if !stopped[id] {
					t.Errorf("strict defence should stop %s\n%s", id, stdout.String())
				}
			}
			if rep.FalsePos != 0 || rep.BenignCalls < 8 {
				t.Errorf("strict defence: %d false positives over %d calls\n%s", rep.FalsePos, rep.BenignCalls, stdout.String())
			}
		case "vulnerable":
			if code != exitFindings {
				t.Fatalf("permissive defence should fail the threshold: exit %d\n%s", code, stdout.String())
			}
			if rep.Stopped != 0 {
				t.Errorf("permissive defence stopped %d attacks\n%s", rep.Stopped, stdout.String())
			}
		}
		if canaryRe.Match(b) {
			t.Error("defence report contains a raw canary value")
		}
	}
}

func TestDefendNeedsImage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Main(context.Background(), []string{"defend", "--yes"}, strings.NewReader(""), &out, &errb, sandbox.Runner{}); code != exitError {
		t.Fatalf("exit %d", code)
	}
}
