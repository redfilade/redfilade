// Command redfilade is the Redfilade CLI.
//
//	redfilade version
//	redfilade scenario validate [DIR...]
//	redfilade range run DIR --build vulnerable|secure [--yes] [--out DIR]
//	redfilade range gate [DIR...] [--yes] [--out DIR] [--junit FILE]
//	redfilade test --image IMAGE [--server "CMD ARGS"] --level L1 [--yes] [--sarif FILE] [--junit FILE] [--out DIR]
//
// Exit codes: 0 pass, 1 findings or gate failure, 2 usage error, refusal or
// inconclusive run.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/redfilade/redfilade/internal/battery"
	"github.com/redfilade/redfilade/internal/consent"
	"github.com/redfilade/redfilade/internal/oracle"
	"github.com/redfilade/redfilade/internal/report"
	"github.com/redfilade/redfilade/internal/run"
	"github.com/redfilade/redfilade/internal/sandbox"
	"github.com/redfilade/redfilade/internal/scenario"
	"github.com/redfilade/redfilade/internal/version"
)

const (
	exitPass     = 0
	exitFindings = 1
	exitError    = 2
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(Main(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, sandbox.Runner{Binary: os.Getenv("REDFILADE_CONTAINER_CLI")}))
}

// Main is the testable entry point.
func Main(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, runner sandbox.Runner) int {
	if len(args) == 0 {
		usage(stderr)
		return exitError
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintf(stdout, "redfilade %s (%s)\n", version.Version, version.Commit)
		return exitPass
	case "scenario":
		if len(args) < 2 || args[1] != "validate" {
			usage(stderr)
			return exitError
		}
		return cmdValidate(args[2:], stdout, stderr)
	case "range":
		if len(args) < 2 {
			usage(stderr)
			return exitError
		}
		switch args[1] {
		case "run":
			return cmdRangeRun(ctx, args[2:], stdin, stdout, stderr, runner)
		case "gate":
			return cmdRangeGate(ctx, args[2:], stdin, stdout, stderr, runner)
		}
	case "test":
		return cmdTest(ctx, args[1:], stdin, stdout, stderr, runner)
	case "help", "-h", "--help":
		usage(stdout)
		return exitPass
	}
	usage(stderr)
	return exitError
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Redfilade, the open MCP red-team range.

Usage:
  redfilade version
  redfilade scenario validate [DIR...]
  redfilade range run DIR --build vulnerable|secure [--yes] [--out DIR]
  redfilade range gate [DIR...] [--yes] [--out DIR] [--junit FILE]
  redfilade test --image IMAGE [--server "CMD ARGS"] --level L1 [--yes]
                 [--sarif FILE] [--junit FILE] [--out DIR] [--location PATH]

Targets always run in an isolated container cell, never directly on your
machine. Only test servers you own or are authorised to test.
`)
}

// --- scenario validate -----------------------------------------------------

func scenarioDirs(args []string) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	m, err := filepath.Glob(filepath.Join("scenarios", "*", scenario.FileName))
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, f := range m {
		dirs = append(dirs, filepath.Dir(f))
	}
	sort.Strings(dirs)
	if len(dirs) == 0 {
		return nil, errors.New("no scenarios found under scenarios/")
	}
	return dirs, nil
}

func cmdValidate(args []string, stdout, stderr io.Writer) int {
	dirs, err := scenarioDirs(args)
	if err != nil {
		fmt.Fprintln(stderr, "redfilade:", err)
		return exitError
	}
	code := exitPass
	for _, d := range dirs {
		m, err := scenario.Load(d)
		if err != nil {
			fmt.Fprintln(stderr, "invalid:", report.Clean(err.Error(), 2000))
			code = exitError
			continue
		}
		for _, s := range m.Exploit {
			if s.Battery != "" {
				if _, ok := battery.Get(s.Battery); !ok {
					fmt.Fprintf(stderr, "invalid: %s: unknown battery attack %q\n", d, s.Battery)
					code = exitError
				}
			}
		}
		if code == exitPass {
			fmt.Fprintf(stdout, "ok  %s  (%s, %s, family %s)\n", m.ID, m.Kind, m.Level, m.Family)
		}
	}
	return code
}

// --- shared helpers ------------------------------------------------------------

type common struct {
	yes     bool
	out     string
	timeout time.Duration
}

func addCommon(fs *flag.FlagSet, c *common) {
	fs.BoolVar(&c.yes, "yes", false, "skip the consent prompt (required when not on a terminal, e.g. in CI)")
	fs.StringVar(&c.out, "out", "redfilade-results", "directory for evidence and reports")
	fs.DurationVar(&c.timeout, "timeout", 120*time.Second, "limit for each run")
}

func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// approve shows the consent screen and decides.
func approve(p consent.Plan, c common, stdin io.Reader, stdout, stderr io.Writer) bool {
	if err := p.Check(); err != nil {
		fmt.Fprintln(stderr, "redfilade:", err)
		return false
	}
	if c.yes {
		fmt.Fprint(stdout, p.Render())
		fmt.Fprintln(stdout, "\n  --yes given: running without a prompt.")
		return true
	}
	if !isTerminal(stdin) {
		fmt.Fprintln(stderr, "redfilade: not running on a terminal; review the plan and pass --yes to run non-interactively")
		fmt.Fprint(stderr, p.Render())
		return false
	}
	return consent.Ask(p, stdin, stdout)
}

func writeFile(dir, name string, write func(io.Writer) error) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, name)
	if st, err := os.Lstat(p); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing to write through symlink %s", p)
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	if err := write(f); err != nil {
		f.Close()
		return "", err
	}
	return p, f.Close()
}

func opts(ctx context.Context, runner sandbox.Runner, c common) (run.Options, sandbox.Tier) {
	tier := runner.DetectTier(ctx)
	return run.Options{Runner: runner, Tier: tier, Deadline: c.timeout, Version: version.Version, Commit: version.Commit}, tier
}

func summary(w io.Writer, label string, ev *report.Evidence) {
	fmt.Fprintf(w, "%-40s %s", label, ev.Oracle.Verdict)
	if n := len(ev.Oracle.Findings); n > 0 {
		var facts []string
		seen := map[string]bool{}
		for _, f := range ev.Oracle.Findings {
			k := f.Fact
			if f.Detector != "" {
				k += ":" + f.Detector
			}
			if !seen[k] {
				seen[k] = true
				facts = append(facts, k)
			}
		}
		fmt.Fprintf(w, "  (%s)", strings.Join(facts, ", "))
	}
	fmt.Fprintln(w)
	for _, e := range ev.Errors {
		fmt.Fprintln(w, "    note:", report.Clean(e, 300))
	}
}

// --- range run / gate ------------------------------------------------------

func cmdRangeRun(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, runner sandbox.Runner) int {
	fs := flag.NewFlagSet("range run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	addCommon(fs, &c)
	build := fs.String("build", "", "which twin to run: vulnerable or secure")
	dir, rest := splitPositional(args)
	if err := fs.Parse(rest); err != nil || dir == "" || (*build != "vulnerable" && *build != "secure") {
		fmt.Fprintln(stderr, "usage: redfilade range run DIR --build vulnerable|secure [--yes]")
		return exitError
	}
	m, err := scenario.Load(dir)
	if err != nil {
		fmt.Fprintln(stderr, "redfilade:", report.Clean(err.Error(), 2000))
		return exitError
	}
	o, tier := opts(ctx, runner, c)
	if !approve(consent.FromManifest(m, *build, tier, false), c, stdin, stdout, stderr) {
		return exitError
	}
	ev, err := run.Scenario(ctx, m, *build, o)
	if err != nil {
		fmt.Fprintln(stderr, "redfilade:", err)
		return exitError
	}
	summary(stdout, m.ID+" ["+*build+"]", ev)
	if _, err := writeFile(c.out, "evidence-"+m.ID+"-"+*build+".json", func(w io.Writer) error { return report.WriteEvidence(w, ev) }); err != nil {
		fmt.Fprintln(stderr, "redfilade:", err)
		return exitError
	}
	switch ev.Oracle.Verdict {
	case oracle.Exploited:
		return exitFindings
	case oracle.NotExploited:
		return exitPass
	}
	return exitError
}

func cmdRangeGate(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, runner sandbox.Runner) int {
	fs := flag.NewFlagSet("range gate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	addCommon(fs, &c)
	junit := fs.String("junit", "", "write a JUnit report to this file")
	var dirs []string
	rest := args
	for len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		dirs = append(dirs, rest[0])
		rest = rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return exitError
	}
	dirs = append(dirs, fs.Args()...)
	dirs, err := scenarioDirs(dirs)
	if err != nil {
		fmt.Fprintln(stderr, "redfilade:", err)
		return exitError
	}
	o, tier := opts(ctx, runner, c)
	var cases []report.Case
	failed := false
	for _, d := range dirs {
		m, err := scenario.Load(d)
		if err != nil {
			fmt.Fprintln(stderr, "redfilade:", report.Clean(err.Error(), 2000))
			return exitError
		}
		for _, build := range []string{"vulnerable", "secure"} {
			if !approve(consent.FromManifest(m, build, tier, false), c, stdin, stdout, stderr) {
				return exitError
			}
			ev, err := run.Scenario(ctx, m, build, o)
			if err != nil {
				fmt.Fprintln(stderr, "redfilade:", err)
				return exitError
			}
			want := build == "vulnerable"
			label := m.ID + " [" + build + "]"
			summary(stdout, label, ev)
			ok := (ev.Oracle.Verdict == oracle.Exploited) == want && ev.Oracle.Verdict != oracle.Inconclusive
			if !ok {
				failed = true
				fmt.Fprintf(stdout, "    GATE FAILED: expected %s\n", map[bool]string{true: "exploited", false: "not_exploited"}[want])
			}
			cases = append(cases, report.Case{Name: label, Evidence: ev, WantExploited: want})
			if _, err := writeFile(c.out, "evidence-"+m.ID+"-"+build+".json", func(w io.Writer) error { return report.WriteEvidence(w, ev) }); err != nil {
				fmt.Fprintln(stderr, "redfilade:", err)
				return exitError
			}
		}
	}
	if *junit != "" {
		if _, err := writeFile(filepath.Dir(*junit), filepath.Base(*junit), func(w io.Writer) error { return report.WriteJUnit(w, "redfilade range gate", cases) }); err != nil {
			fmt.Fprintln(stderr, "redfilade:", err)
			return exitError
		}
	}
	if failed {
		fmt.Fprintln(stdout, "\nRange gate: FAILED")
		return exitFindings
	}
	fmt.Fprintf(stdout, "\nRange gate: passed (%d scenarios: every vulnerable twin exploited, every secure twin held)\n", len(dirs))
	return exitPass
}

// --- test (builder's own server) --------------------------------------------

func cmdTest(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, runner sandbox.Runner) int {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	addCommon(fs, &c)
	image := fs.String("image", "", "container image of the MCP server under test (required)")
	server := fs.String("server", "", `command to start the server inside the image, e.g. "node dist/index.js"`)
	level := fs.String("level", "L1", "test level (L1 available today)")
	protocol := fs.String("protocol", "2026-07-28", "MCP protocol revision: 2026-07-28 or 2025-11-25")
	sarif := fs.String("sarif", "", "write SARIF 2.1.0 to this file")
	junit := fs.String("junit", "", "write JUnit XML to this file")
	location := fs.String("location", "README.md", "repository path SARIF results are attached to")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if *image == "" {
		fmt.Fprintln(stderr, "redfilade: --image is required. Redfilade never runs a server directly on your machine; package it as a container image first.")
		return exitError
	}
	if *protocol != "2026-07-28" && *protocol != "2025-11-25" {
		fmt.Fprintln(stderr, "redfilade: --protocol must be 2026-07-28 or 2025-11-25")
		return exitError
	}
	if len(battery.ForLevel(*level)) == 0 {
		fmt.Fprintf(stderr, "redfilade: level %s has no attacks yet (available: L1)\n", *level)
		return exitError
	}
	o, tier := opts(ctx, runner, c)
	p := consent.Plan{ScenarioID: "battery-" + strings.ToLower(*level), Kind: "battery", Level: *level, Family: "multiple",
		Risk: "low", Build: "target", Image: *image, Network: "none", Tier: tier}
	if !approve(p, c, stdin, stdout, stderr) {
		return exitError
	}
	ev, err := run.Target(ctx, *image, strings.Fields(*server), *protocol, *level, o)
	if err != nil {
		fmt.Fprintln(stderr, "redfilade:", err)
		return exitError
	}
	summary(stdout, *image+" ["+*level+"]", ev)
	if _, err := writeFile(c.out, "evidence-test-"+*level+".json", func(w io.Writer) error { return report.WriteEvidence(w, ev) }); err != nil {
		fmt.Fprintln(stderr, "redfilade:", err)
		return exitError
	}
	if *sarif != "" {
		if _, err := writeFile(filepath.Dir(*sarif), filepath.Base(*sarif), func(w io.Writer) error {
			return report.WriteSARIF(w, ev, version.Version, *location)
		}); err != nil {
			fmt.Fprintln(stderr, "redfilade:", err)
			return exitError
		}
	}
	if *junit != "" {
		if _, err := writeFile(filepath.Dir(*junit), filepath.Base(*junit), func(w io.Writer) error {
			return report.WriteJUnit(w, "redfilade test "+*level, []report.Case{{Name: *image, Evidence: ev, WantExploited: false}})
		}); err != nil {
			fmt.Fprintln(stderr, "redfilade:", err)
			return exitError
		}
	}
	switch ev.Oracle.Verdict {
	case oracle.Exploited:
		return exitFindings
	case oracle.NotExploited:
		return exitPass
	}
	return exitError
}

// splitPositional takes the first non-flag argument out of args, skipping the
// values of flags that take one.
func splitPositional(args []string) (string, []string) {
	takesValue := map[string]bool{}
	for _, f := range []string{"build", "out", "timeout"} {
		takesValue["-"+f] = true
		takesValue["--"+f] = true
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			if takesValue[a] {
				i++
			}
			continue
		}
		rest := append(append([]string{}, args[:i]...), args[i+1:]...)
		return a, rest
	}
	return "", args
}
