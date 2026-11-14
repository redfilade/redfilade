package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/redfilade/redfilade/internal/sandbox"
)

// fakeDocker stands in for the container CLI in tests: it maps image names to
// locally built binaries and runs them with the cell's env and world. The
// hardening flags themselves are covered by the sandbox package's tests; the
// real container path runs in CI (range-gate job).
const fakeDocker = `#!/usr/bin/env bash
set -euo pipefail
cmd="$1"; shift
case "$cmd" in
  info) echo '{"runc":{"path":"runc"}}'; exit 0 ;;
  rm) exit 0 ;;
  run) ;;
  *) echo "fake docker: unsupported $cmd" >&2; exit 1 ;;
esac
envs=(); world=""
while [ $# -gt 0 ]; do
  case "$1" in
    --) shift; break ;;
    --env) envs+=("$2"); shift 2 ;;
    --mount) world="${2#*src=}"; world="${world%%,dst=*}"; shift 2 ;;
    --rm|-i|--read-only) shift ;;
    *) shift 2 ;;
  esac
done
image="$1"; shift
bin=""
IFS=';' read -ra pairs <<< "$FAKE_IMAGES"
for p in "${pairs[@]}"; do [ "${p%%=*}" = "$image" ] && bin="${p#*=}"; done
[ -n "$bin" ] || { echo "fake docker: no image $image" >&2; exit 125; }
exec env -i WORLD_DIR="$world" "${envs[@]}" "$bin" "$@"
`

func buildTwins(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("bash shim")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	root, _ := filepath.Abs("../..")
	var images []string
	for _, mode := range []string{"vulnerable", "secure"} {
		out := filepath.Join(dir, "leaky-errors-"+mode)
		cmd := exec.Command("go", "build", "-ldflags", "-X main.mode="+mode, "-o", out, "./targets/leaky-errors")
		cmd.Dir = root
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", mode, err, b)
		}
		images = append(images, "redfilade-target/leaky-errors:"+mode+"="+out)
	}
	shim := filepath.Join(dir, "docker")
	if err := os.WriteFile(shim, []byte(fakeDocker), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_IMAGES", strings.Join(images, ";"))
	return shim
}

var canaryRe = regexp.MustCompile(`CANARY_[A-Z0-9_]+_[A-Z2-7]{26}`)

func TestRangeGateEndToEnd(t *testing.T) {
	shim := buildTwins(t)
	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	junit := filepath.Join(out, "gate.xml")
	code := Main(context.Background(), []string{"range", "gate", "../../scenarios/l1-leaky-errors", "--yes", "--out", out, "--junit", junit},
		strings.NewReader(""), &stdout, &stderr, sandbox.Runner{Binary: shim})
	if code != exitPass {
		t.Fatalf("gate exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	if !regexp.MustCompile(`l1-leaky-errors \[vulnerable\]\s+exploited`).MatchString(stdout.String()) ||
		!regexp.MustCompile(`l1-leaky-errors \[secure\]\s+not_exploited`).MatchString(stdout.String()) {
		t.Fatalf("unexpected summary:\n%s", stdout.String())
	}
	for _, f := range []string{"evidence-l1-leaky-errors-vulnerable.json", "evidence-l1-leaky-errors-secure.json", "gate.xml"} {
		b, err := os.ReadFile(filepath.Join(out, f))
		if err != nil {
			t.Fatal(err)
		}
		if canaryRe.Match(b) {
			t.Errorf("%s contains a raw canary value", f)
		}
	}
	var ev map[string]any
	b, _ := os.ReadFile(filepath.Join(out, "evidence-l1-leaky-errors-vulnerable.json"))
	if err := json.Unmarshal(b, &ev); err != nil {
		t.Fatal(err)
	}
	if ev["signature"].(map[string]any)["status"] != "unsigned" {
		t.Error("local evidence must be labelled unsigned")
	}
	if !strings.Contains(string(b), "[canary:DB_PASSWORD]") {
		t.Error("vulnerable evidence should show the redacted canary leak")
	}
}

func TestBuilderTestEndToEnd(t *testing.T) {
	shim := buildTwins(t)
	for _, tc := range []struct {
		build string
		code  int
	}{{"vulnerable", exitFindings}, {"secure", exitPass}} {
		out := t.TempDir()
		sarif := filepath.Join(out, "results.sarif")
		var stdout, stderr bytes.Buffer
		code := Main(context.Background(), []string{"test", "--image", "redfilade-target/leaky-errors:" + tc.build, "--level", "L1", "--yes", "--out", out, "--sarif", sarif},
			strings.NewReader(""), &stdout, &stderr, sandbox.Runner{Binary: shim})
		if code != tc.code {
			t.Fatalf("%s: exit %d, want %d\n%s\n%s", tc.build, code, tc.code, stdout.String(), stderr.String())
		}
		b, err := os.ReadFile(sarif)
		if err != nil {
			t.Fatal(err)
		}
		var log struct {
			Runs []struct {
				Results []any `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(b, &log); err != nil {
			t.Fatal(err)
		}
		n := len(log.Runs[0].Results)
		if (tc.build == "vulnerable") != (n > 0) {
			t.Errorf("%s: %d SARIF results", tc.build, n)
		}
	}
}

func TestNonInteractiveNeedsYes(t *testing.T) {
	shim := buildTwins(t)
	var stdout, stderr bytes.Buffer
	code := Main(context.Background(), []string{"test", "--image", "redfilade-target/leaky-errors:secure"},
		strings.NewReader("y\n"), &stdout, &stderr, sandbox.Runner{Binary: shim})
	if code != exitError || !strings.Contains(stderr.String(), "--yes") {
		t.Fatalf("ran without consent: exit %d\n%s", code, stderr.String())
	}
}

func TestRefusesWithoutContainerRuntime(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Main(context.Background(), []string{"test", "--image", "x/y:z", "--yes"},
		strings.NewReader(""), &stdout, &stderr, sandbox.Runner{Binary: "/nonexistent/docker"})
	if code != exitError || !strings.Contains(stderr.String(), "never runs targets directly") {
		t.Fatalf("exit %d\n%s", code, stderr.String())
	}
}

func TestImageIsRequired(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Main(context.Background(), []string{"test", "--server", "npx evil"}, strings.NewReader(""), &stdout, &stderr, sandbox.Runner{})
	if code != exitError || !strings.Contains(stderr.String(), "--image is required") {
		t.Fatalf("exit %d\n%s", code, stderr.String())
	}
}

func TestValidateScenarios(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Main(context.Background(), []string{"scenario", "validate", "../../scenarios/l1-leaky-errors"}, nil, &stdout, &stderr, sandbox.Runner{}); code != exitPass {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

func TestSplitPositional(t *testing.T) {
	dir, rest := splitPositional([]string{"--build", "vulnerable", "scenarios/x", "--yes"})
	if dir != "scenarios/x" || strings.Join(rest, " ") != "--build vulnerable --yes" {
		t.Fatalf("dir=%q rest=%v", dir, rest)
	}
}
