package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
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
  network) exit 0 ;;
  rm)
    for n in "$@"; do
      case "$n" in redfilade-sink-*) [ -f "$FAKE_STATE/$n.pid" ] && kill "$(cat "$FAKE_STATE/$n.pid")" 2>/dev/null; rm -f "$FAKE_STATE/$n.pid" ;; esac
    done
    exit 0 ;;
  run) ;;
  *) echo "fake docker: unsupported $cmd" >&2; exit 1 ;;
esac
envs=(); world=""; detach=0; name=""; network="none"
while [ $# -gt 0 ]; do
  case "$1" in
    --) shift; break ;;
    --env) envs+=("$2"); shift 2 ;;
    --mount) world="${2#*src=}"; world="${world%%,dst=*}"; shift 2 ;;
    --name) name="$2"; shift 2 ;;
    --network) network="$2"; shift 2 ;;
    -d) detach=1; shift ;;
    --rm|-i|--read-only) shift ;;
    *) shift 2 ;;
  esac
done
image="$1"; shift
if [ "$detach" = 1 ]; then
  # The egress sink: run the real sink binary on loopback, logging to its mount.
  env -i SINK_ADDR="127.0.0.1:$FAKE_SINK_PORT" SINK_LOG_DIR="$world" "${envs[@]}" "$FAKE_SINK_BIN" >/dev/null 2>&1 &
  echo $! > "$FAKE_STATE/$name.pid"
  exit 0
fi
proxy=()
case "$network" in redfilade-net-*) proxy=(HTTP_PROXY="http://127.0.0.1:$FAKE_SINK_PORT") ;; esac
bin=""
IFS=';' read -ra pairs <<< "$FAKE_IMAGES"
for p in "${pairs[@]}"; do [ "${p%%=*}" = "$image" ] && bin="${p#*=}"; done
[ -n "$bin" ] || { echo "fake docker: no image $image" >&2; exit 125; }
exec env -i WORLD_DIR="$world" "${proxy[@]}" "${envs[@]}" "$bin" "$@"
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
	build := func(pkg, mode, out string) {
		cmd := exec.Command("go", "build", "-ldflags", "-X main.mode="+mode, "-o", out, "./"+pkg)
		cmd.Dir = root
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s %s: %v\n%s", pkg, mode, err, b)
		}
	}
	var images []string
	for _, target := range targetNames {
		for _, mode := range []string{"vulnerable", "secure"} {
			out := filepath.Join(dir, target+"-"+mode)
			build("targets/"+target, mode, out)
			images = append(images, "redfilade-target/"+target+":"+mode+"="+out)
		}
	}
	sinkBin := filepath.Join(dir, "sink")
	build("infra/sink", "", sinkBin)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	state := filepath.Join(dir, "state")
	_ = os.Mkdir(state, 0o755)
	t.Setenv("FAKE_SINK_BIN", sinkBin)
	t.Setenv("FAKE_SINK_PORT", strconv.Itoa(port))
	t.Setenv("FAKE_STATE", state)
	shim := filepath.Join(dir, "docker")
	if err := os.WriteFile(shim, []byte(fakeDocker), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_IMAGES", strings.Join(images, ";"))
	return shim
}

var canaryRe = regexp.MustCompile(`CANARY_[A-Z0-9_]+_[A-Z2-7]{26}`)

var targetNames = []string{"leaky-errors", "path-traversal", "ssrf", "secrets-in-output", "tool-poisoning"}

func allScenarioDirs(t *testing.T) []string {
	m, err := filepath.Glob("../../scenarios/*/scenario.json")
	if err != nil || len(m) < 4 {
		t.Fatalf("scenarios: %v %v", m, err)
	}
	var dirs []string
	for _, f := range m {
		dirs = append(dirs, filepath.Dir(f))
	}
	return dirs
}

func TestRangeGateEndToEnd(t *testing.T) {
	shim := buildTwins(t)
	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	junit := filepath.Join(out, "gate.xml")
	// No directories: the gate runs every scenario built into the binary.
	args := []string{"range", "gate", "--yes", "--out", out, "--junit", junit}
	code := Main(context.Background(), args,
		strings.NewReader(""), &stdout, &stderr, sandbox.Runner{Binary: shim})
	if code != exitPass {
		t.Fatalf("gate exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	for _, id := range []string{"l1-leaky-errors", "l1-tool-poisoning", "l2-path-traversal", "l2-ssrf", "l2-secrets-in-output"} {
		if !regexp.MustCompile(id+` \[vulnerable\]\s+exploited`).MatchString(stdout.String()) ||
			!regexp.MustCompile(id+` \[secure\]\s+not_exploited`).MatchString(stdout.String()) {
			t.Fatalf("unexpected summary for %s:\n%s", id, stdout.String())
		}
	}
	files, _ := filepath.Glob(filepath.Join(out, "*"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if canaryRe.Match(b) {
			t.Errorf("%s contains a raw canary value", f)
		}
	}
	ssrf, _ := os.ReadFile(filepath.Join(out, "evidence-l2-ssrf-vulnerable.json"))
	if !strings.Contains(string(ssrf), "sink.redfilade.test") || !strings.Contains(string(ssrf), "egress_reached_sink") {
		t.Error("SSRF evidence should record the request the sink received")
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

func TestBuilderL2EndToEnd(t *testing.T) {
	shim := buildTwins(t)
	for _, tc := range []struct {
		image string
		code  int
	}{
		{"path-traversal:vulnerable", exitFindings}, {"path-traversal:secure", exitPass},
		{"ssrf:vulnerable", exitFindings}, {"ssrf:secure", exitPass},
		{"secrets-in-output:vulnerable", exitFindings}, {"secrets-in-output:secure", exitPass},
	} {
		out := t.TempDir()
		var stdout, stderr bytes.Buffer
		code := Main(context.Background(), []string{"test", "--image", "redfilade-target/" + tc.image, "--level", "L2", "--yes", "--out", out},
			strings.NewReader(""), &stdout, &stderr, sandbox.Runner{Binary: shim})
		if code != tc.code {
			t.Errorf("%s: exit %d, want %d\n%s\n%s", tc.image, code, tc.code, stdout.String(), stderr.String())
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

// copyPack copies a built-in scenario directory so it counts as an external pack.
func copyPack(t *testing.T, id string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join("../../scenarios", id, "scenario.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scenario.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestExternalPackPolicy(t *testing.T) {
	shim := buildTwins(t)
	dir := copyPack(t, "l1-leaky-errors")
	run := func(extra ...string) (int, string) {
		var stdout, stderr bytes.Buffer
		args := append([]string{"range", "run", dir, "--build", "vulnerable", "--yes", "--out", t.TempDir()}, extra...)
		code := Main(context.Background(), args, strings.NewReader(""), &stdout, &stderr, sandbox.Runner{Binary: shim})
		return code, stdout.String() + stderr.String()
	}
	if code, out := run(); code != exitError || !strings.Contains(out, "unsigned") {
		t.Fatalf("an unsigned pack must be refused by default (exit %d):\n%s", code, out)
	}
	if code, out := run("--allow-unsigned", "--confirm", "wrong-id"); code != exitError {
		t.Fatalf("a wrong confirmation must be refused (exit %d):\n%s", code, out)
	}
	if code, out := run("--allow-unsigned", "--confirm", "l1-leaky-errors"); code != exitError || !strings.Contains(out, "digest") {
		t.Fatalf("a non-interactive unsigned run needs an allowed digest (exit %d):\n%s", code, out)
	}
	var dig bytes.Buffer
	if code := Main(context.Background(), []string{"pack", "digest", dir}, strings.NewReader(""), &dig, io.Discard, sandbox.Runner{Binary: shim}); code != exitPass {
		t.Fatalf("pack digest exit %d", code)
	}
	d := strings.TrimSpace(dig.String())
	if !strings.HasPrefix(d, "sha256:") {
		t.Fatalf("digest %q", d)
	}
	code, out := run("--allow-unsigned", "--confirm", "l1-leaky-errors", "--allow-digest", d)
	if code != exitFindings || !strings.Contains(out, "EXTERNAL PACK") {
		t.Fatalf("an allowed, confirmed pack should run and be exploited (exit %d):\n%s", code, out)
	}
	// Changing one byte changes the digest, so the same allowance no longer applies.
	b, _ := os.ReadFile(filepath.Join(dir, "scenario.json"))
	if err := os.WriteFile(filepath.Join(dir, "scenario.json"), append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out := run("--allow-unsigned", "--confirm", "l1-leaky-errors", "--allow-digest", d); code != exitError {
		t.Fatalf("a modified pack must not match the old digest (exit %d):\n%s", code, out)
	}
}

func TestBuiltinByID(t *testing.T) {
	shim := buildTwins(t)
	var stdout, stderr bytes.Buffer
	code := Main(context.Background(), []string{"range", "run", "l2-secrets-in-output", "--build", "secure", "--yes", "--out", t.TempDir()},
		strings.NewReader(""), &stdout, &stderr, sandbox.Runner{Binary: shim})
	if code != exitPass || !strings.Contains(stdout.String(), "built into this Redfilade binary") {
		t.Fatalf("exit %d\n%s%s", code, stdout.String(), stderr.String())
	}
	code = Main(context.Background(), []string{"range", "run", "no-such-scenario", "--build", "secure", "--yes"},
		strings.NewReader(""), &stdout, &stderr, sandbox.Runner{Binary: shim})
	if code != exitError {
		t.Fatalf("unknown id should fail, got %d", code)
	}
}
