package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/redfilade/redfilade/internal/sandbox"
)

// TestRangeRunExplains checks what a first-time user sees after one run:
// the scenario's purpose, what the attack achieved, what was not observed,
// where the evidence is and how to compare with the other twin.
func TestRangeRunExplains(t *testing.T) {
	shim := buildTwins(t)
	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Main(context.Background(), []string{"range", "run", "l2-path-traversal", "--build", "vulnerable", "--yes", "--out", out},
		strings.NewReader(""), &stdout, &stderr, sandbox.Runner{Binary: shim})
	if code != exitFindings {
		t.Fatalf("exit %d\n%s\n%s", code, stdout.String(), stderr.String())
	}
	s := stdout.String()
	for _, want := range []string{"About this scenario", "What the attack achieved", "the secret API_KEY was sent back",
		"the file config/app.env was changed", "What Redfilade could not see", "Evidence (every message, redacted):",
		"redfilade range run l2-path-traversal --build secure"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if canaryRe.MatchString(s) {
		t.Error("terminal output contains a raw canary")
	}
}

func TestGateAsksOnce(t *testing.T) {
	shim := buildTwins(t)
	var stdout, stderr bytes.Buffer
	code := Main(context.Background(), []string{"range", "gate", "l1-leaky-errors", "l2-ssrf", "--yes", "--out", t.TempDir()},
		strings.NewReader(""), &stdout, &stderr, sandbox.Runner{Binary: shim})
	if code != exitPass {
		t.Fatalf("exit %d\n%s\n%s", code, stdout.String(), stderr.String())
	}
	if n := strings.Count(stdout.String(), "Redfilade is about to run"); n != 1 {
		t.Errorf("gate showed %d consent screens, want 1:\n%s", n, stdout.String())
	}
}

func TestHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Main(context.Background(), []string{"help"}, strings.NewReader(""), &stdout, &stderr, sandbox.Runner{}); code != exitPass {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"test --url URL", "--token-env", "--model", "--confirm ID", "defend --defence-image"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("help missing %q", want)
		}
	}
}
