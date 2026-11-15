// Command redfilade is the Redfilade CLI.
//
//	redfilade version
//	redfilade scenario list
//	redfilade scenario validate [DIR...]
//	redfilade pack digest DIR | pack verify DIR
//	redfilade triage summarize DIR
//	redfilade domain challenge DOMAIN | domain verify DOMAIN | domain list
//	redfilade hostile-server [--probes all] [--log FILE]   (stdio; for your own MCP client)
//	redfilade client-report FILE [--sarif FILE]
//	redfilade range run ID|DIR --build vulnerable|secure [--yes] [--out DIR]
//	redfilade range gate [ID|DIR...] [--yes] [--out DIR] [--junit FILE]
//	redfilade test --image IMAGE [--server "CMD ARGS"] --level L1 [--yes] [--sarif FILE] [--junit FILE] [--out DIR]
//
// Exit codes: 0 pass, 1 findings or gate failure, 2 usage error, refusal or
// inconclusive run.
package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	neturl "net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/redfilade/redfilade/internal/agent"
	"github.com/redfilade/redfilade/internal/battery"
	"github.com/redfilade/redfilade/internal/consent"
	"github.com/redfilade/redfilade/internal/domain"
	"github.com/redfilade/redfilade/internal/hostile"
	"github.com/redfilade/redfilade/internal/mcp"
	"github.com/redfilade/redfilade/internal/oracle"
	"github.com/redfilade/redfilade/internal/pack"
	"github.com/redfilade/redfilade/internal/report"
	"github.com/redfilade/redfilade/internal/run"
	"github.com/redfilade/redfilade/internal/sandbox"
	"github.com/redfilade/redfilade/internal/scenario"
	"github.com/redfilade/redfilade/internal/triage"
	"github.com/redfilade/redfilade/internal/version"
	"github.com/redfilade/redfilade/scenarios"
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
		if len(args) >= 2 && args[1] == "validate" {
			return cmdValidate(ctx, args[2:], stdout, stderr)
		}
		if len(args) >= 2 && args[1] == "list" {
			return cmdList(stdout, stderr)
		}
		usage(stderr)
		return exitError
	case "pack":
		if len(args) == 3 && (args[1] == "digest" || args[1] == "verify") {
			return cmdPack(ctx, args[1], args[2], stdout, stderr)
		}
		usage(stderr)
		return exitError
	case "domain":
		return cmdDomain(ctx, args[1:], stdout, stderr)
	case "hostile-server":
		return cmdHostileServer(ctx, args[1:], stdin, stdout, stderr)
	case "client-report":
		return cmdClientReport(args[1:], stdout, stderr)
	case "triage":
		if len(args) == 3 && args[1] == "summarize" {
			rows, skipped, err := triage.Load(args[2])
			if err != nil {
				fmt.Fprintln(stderr, "redfilade: cannot read evidence directory")
				return exitError
			}
			if err := triage.Markdown(stdout, rows, skipped); err != nil {
				return exitError
			}
			return exitPass
		}
		usage(stderr)
		return exitError
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
  redfilade scenario list
  redfilade scenario validate [DIR...]
  redfilade pack digest DIR
  redfilade pack verify DIR
  redfilade triage summarize DIR
  redfilade domain challenge DOMAIN
  redfilade domain verify DOMAIN
  redfilade domain list
  redfilade hostile-server [--probes all] [--log FILE]
  redfilade client-report FILE [--sarif FILE] [--out DIR]
  redfilade range run ID|DIR --build vulnerable|secure [--yes] [--out DIR]
  redfilade range gate [ID|DIR...] [--yes] [--out DIR] [--junit FILE]
  redfilade test --image IMAGE [--server "CMD ARGS"] --level L1 [--yes]
                 [--sarif FILE] [--junit FILE] [--out DIR] [--location PATH]

Scenarios built into Redfilade run by id. A directory is an external pack:
it must carry a valid signature, or be run with --allow-unsigned and its id
confirmed. Non-interactive runs must also list the pack's exact digest with
--allow-digest or --allowlist FILE.

Targets always run in an isolated container cell, never directly on your
machine. Only test servers you own or are authorised to test.
`)
}

// --- scenario list / validate, pack ------------------------------------------

func cmdList(stdout, stderr io.Writer) int {
	all, err := scenarios.Builtins()
	if err != nil {
		fmt.Fprintln(stderr, "redfilade:", err)
		return exitError
	}
	for _, m := range all {
		fmt.Fprintf(stdout, "%-24s %s  family %s  network %-4s  %s\n", m.ID, m.Level, m.Family, m.Needs.Network, report.Clean(m.Title, 80))
	}
	return exitPass
}

func checkBatteries(m *scenario.Manifest) error {
	for _, s := range m.Exploit {
		if s.Battery != "" {
			if _, ok := battery.Get(s.Battery); !ok {
				return fmt.Errorf("%s: unknown battery attack %q", m.ID, s.Battery)
			}
		}
	}
	return nil
}

func cmdValidate(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	code := exitPass
	if len(args) == 0 {
		all, err := scenarios.Builtins()
		if err != nil {
			fmt.Fprintln(stderr, "invalid:", report.Clean(err.Error(), 2000))
			return exitError
		}
		for _, m := range all {
			if err := checkBatteries(m); err != nil {
				fmt.Fprintln(stderr, "invalid:", err)
				code = exitError
				continue
			}
			fmt.Fprintf(stdout, "ok  %-24s built-in  (%s, %s, family %s)\n", m.ID, m.Kind, m.Level, m.Family)
		}
		return code
	}
	for _, d := range args {
		m, err := scenario.Load(d)
		if err == nil {
			err = checkBatteries(m)
		}
		if err != nil {
			fmt.Fprintln(stderr, "invalid:", report.Clean(err.Error(), 2000))
			code = exitError
			continue
		}
		sig, _ := pack.Verifier{}.Check(ctx, d)
		pinned := "images pinned by digest"
		if !m.PinnedImages() {
			pinned = "images NOT pinned by digest"
		}
		fmt.Fprintf(stdout, "ok  %-24s pack %s  signature %s  %s\n", m.ID, pack.Digest(m.Raw), sig, pinned)
	}
	return code
}

func cmdPack(ctx context.Context, sub, dir string, stdout, stderr io.Writer) int {
	m, err := scenario.Load(dir)
	if err != nil {
		fmt.Fprintln(stderr, "redfilade:", report.Clean(err.Error(), 2000))
		return exitError
	}
	if sub == "digest" {
		fmt.Fprintln(stdout, pack.Digest(m.Raw))
		return exitPass
	}
	sig, err := pack.Verifier{}.Check(ctx, dir)
	fmt.Fprintf(stdout, "%s  %s  signature %s\n", m.ID, pack.Digest(m.Raw), sig)
	if err != nil {
		fmt.Fprintln(stderr, "redfilade:", report.Clean(err.Error(), 500))
	}
	if sig != pack.Verified {
		return exitFindings
	}
	return exitPass
}

// --- shared helpers ------------------------------------------------------------

type common struct {
	yes           bool
	out           string
	timeout       time.Duration
	allowUnsigned bool
	confirm       string
	allowDigests  digestList
	allowlist     string
	model         string
	trials        int
}

type digestList []string

func (d *digestList) String() string     { return strings.Join(*d, ",") }
func (d *digestList) Set(v string) error { *d = append(*d, v); return nil }

func addCommon(fs *flag.FlagSet, c *common) {
	fs.BoolVar(&c.yes, "yes", false, "skip the consent prompt (required when not on a terminal, e.g. in CI)")
	fs.StringVar(&c.out, "out", "redfilade-results", "directory for evidence and reports")
	fs.DurationVar(&c.timeout, "timeout", 120*time.Second, "limit for each run")
	fs.BoolVar(&c.allowUnsigned, "allow-unsigned", false, "allow an unsigned external pack (its id must be confirmed)")
	fs.StringVar(&c.confirm, "confirm", "", "the external pack id, confirming you want to run it unsigned")
	fs.Var(&c.allowDigests, "allow-digest", "exact external pack digest allowed in non-interactive runs (repeatable)")
	fs.StringVar(&c.allowlist, "allowlist", "", "file of allowed external pack digests, one per line")
	fs.StringVar(&c.model, "model", "scripted:naive", "model for L3 agent scenarios: scripted:naive, scripted:careful or anthropic:<model-id> (needs ANTHROPIC_API_KEY)")
	fs.IntVar(&c.trials, "trials", 0, "trials per L3 agent scenario (0 = the scenario's default, at most 50)")
}

// target is a scenario resolved from an id (built-in) or a directory (pack).
type target struct {
	m         *scenario.Manifest
	origin    string
	digest    string
	signature string
}

// resolve finds a scenario and decides whether it may run.
func resolve(ctx context.Context, arg string, c common, stdin io.Reader, stdout io.Writer) (*target, error) {
	if !strings.ContainsAny(arg, `/\.`) {
		if m, ok := scenarios.Builtin(arg); ok {
			return &target{m: m, origin: "built-in", signature: "built-in"}, nil
		}
		if _, err := os.Stat(arg); err != nil {
			return nil, fmt.Errorf("no built-in scenario %q (see: redfilade scenario list)", arg)
		}
	}
	m, err := scenario.Load(arg)
	if err != nil {
		return nil, errors.New(report.Clean(err.Error(), 2000))
	}
	if err := checkBatteries(m); err != nil {
		return nil, err
	}
	digest := pack.Digest(m.Raw)
	sig, verr := pack.Verifier{}.Check(ctx, arg)
	if verr != nil {
		fmt.Fprintln(stdout, "  signature check:", report.Clean(verr.Error(), 300))
	}
	allowed := map[string]bool{}
	for _, d := range c.allowDigests {
		allowed[d] = true
	}
	if c.allowlist != "" {
		list, err := pack.ParseAllowlist(c.allowlist)
		if err != nil {
			return nil, err
		}
		for d := range list {
			allowed[d] = true
		}
	}
	interactive := !c.yes && isTerminal(stdin)
	confirm := c.confirm
	if sig != pack.Verified && sig != pack.Invalid && c.allowUnsigned && confirm == "" && interactive {
		fmt.Fprintf(stdout, "\n%s is an UNSIGNED external pack (%s).\nType its id to confirm: ", m.ID, digest)
		line, _ := bufio.NewReader(io.LimitReader(stdin, 128)).ReadString('\n')
		confirm = strings.TrimSpace(line)
	}
	if err := pack.Decide(m, digest, sig, pack.Policy{AllowUnsigned: c.allowUnsigned, Confirm: confirm, AllowedDigests: allowed, Interactive: interactive}); err != nil {
		return nil, err
	}
	return &target{m: m, origin: "external pack", digest: digest, signature: sig}, nil
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
func approve(p consent.Screen, c common, stdin io.Reader, stdout, stderr io.Writer) bool {
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
	if a := ev.Agent; a != nil {
		fmt.Fprintf(w, "    agent %s: hijacked in %d of %d completed trials (%.0f%%, 95%% interval %.0f-%.0f%%)\n",
			a.Model, a.Exploited, a.Completed, a.Rate*100, a.Interval95[0]*100, a.Interval95[1]*100)
	}
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
		fmt.Fprintln(stderr, "usage: redfilade range run ID|DIR --build vulnerable|secure [--yes]")
		return exitError
	}
	t, err := resolve(ctx, dir, c, stdin, stdout)
	if err != nil {
		fmt.Fprintln(stderr, "redfilade:", err)
		return exitError
	}
	m := t.m
	o, tier := opts(ctx, runner, c)
	if !approve(scenarioPlan(m, *build, tier, t, c), c, stdin, stdout, stderr) {
		return exitError
	}
	ev, err := runScenario(ctx, m, *build, o, c)
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
	var targets []*target
	if len(dirs) == 0 {
		all, err := scenarios.Builtins()
		if err != nil {
			fmt.Fprintln(stderr, "redfilade:", err)
			return exitError
		}
		for _, m := range all {
			targets = append(targets, &target{m: m, origin: "built-in", signature: "built-in"})
		}
	}
	for _, d := range dirs {
		t, err := resolve(ctx, d, c, stdin, stdout)
		if err != nil {
			fmt.Fprintln(stderr, "redfilade:", err)
			return exitError
		}
		targets = append(targets, t)
	}
	o, tier := opts(ctx, runner, c)
	var cases []report.Case
	failed := false
	for _, t := range targets {
		m := t.m
		for _, build := range []string{"vulnerable", "secure"} {
			if !approve(scenarioPlan(m, build, tier, t, c), c, stdin, stdout, stderr) {
				return exitError
			}
			ev, err := runScenario(ctx, m, build, o, c)
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
	fmt.Fprintf(stdout, "\nRange gate: passed (%d scenarios: every vulnerable twin exploited, every secure twin held)\n", len(targets))
	return exitPass
}

// --- test (builder's own server) --------------------------------------------

func cmdTest(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, runner sandbox.Runner) int {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	addCommon(fs, &c)
	image := fs.String("image", "", "container image of the MCP server under test (stdio)")
	url := fs.String("url", "", "URL of an MCP server reached over Streamable HTTP (on this machine, or a verified domain)")
	tokenEnv := fs.String("token-env", "", "name of an environment variable holding the server's bearer token")
	foreignEnv := fs.String("foreign-token-env", "", "name of an environment variable holding a valid token issued for a DIFFERENT audience (audience check)")
	server := fs.String("server", "", `command to start the server inside the image, e.g. "node dist/index.js"`)
	level := fs.String("level", "L1", "test level: L1, or L2 (includes L1)")
	protocol := fs.String("protocol", "2026-07-28", "MCP protocol revision: 2026-07-28 or 2025-11-25")
	sarif := fs.String("sarif", "", "write SARIF 2.1.0 to this file")
	junit := fs.String("junit", "", "write JUnit XML to this file")
	location := fs.String("location", "README.md", "repository path SARIF results are attached to")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if *image != "" && *url != "" {
		fmt.Fprintln(stderr, "redfilade: use either --image or --url, not both")
		return exitError
	}
	if *image == "" && *url == "" {
		fmt.Fprintln(stderr, "redfilade: --image or --url is required. Redfilade never runs a server directly on your machine; package it as a container image, or test one you already run with --url.")
		return exitError
	}
	if *protocol != "2026-07-28" && *protocol != "2025-11-25" {
		fmt.Fprintln(stderr, "redfilade: --protocol must be 2026-07-28 or 2025-11-25")
		return exitError
	}
	if len(battery.ForLevel(*level)) == 0 {
		fmt.Fprintf(stderr, "redfilade: level %s has no attacks yet (available: L1, L2)\n", *level)
		return exitError
	}
	if *url != "" {
		return cmdTestRemote(ctx, *url, *tokenEnv, *foreignEnv, *level, *protocol, c, reportFiles{*sarif, *junit, *location}, stdin, stdout, stderr)
	}
	o, tier := opts(ctx, runner, c)
	p := consent.Plan{ScenarioID: "battery-" + strings.ToLower(*level), Kind: "battery", Level: *level, Family: "multiple",
		Risk: "low", Build: "target", Image: *image, Network: "none", Tier: tier}
	for _, a := range battery.ForLevel(*level) {
		if a.Network == "sink" {
			p.Network = "sink"
		}
	}
	if !approve(p, c, stdin, stdout, stderr) {
		return exitError
	}
	ev, err := run.Target(ctx, *image, strings.Fields(*server), *protocol, *level, o)
	if err != nil {
		fmt.Fprintln(stderr, "redfilade:", err)
		return exitError
	}
	return finishTest(ev, *image, *level, c, reportFiles{*sarif, *junit, *location}, stdout, stderr)
}

type reportFiles struct{ sarif, junit, location string }

// finishTest prints the summary, writes the reports and picks the exit code.
func finishTest(ev *report.Evidence, label, level string, c common, rf reportFiles, stdout, stderr io.Writer) int {
	summary(stdout, label+" ["+level+"]", ev)
	if _, err := writeFile(c.out, "evidence-test-"+level+".json", func(w io.Writer) error { return report.WriteEvidence(w, ev) }); err != nil {
		fmt.Fprintln(stderr, "redfilade:", err)
		return exitError
	}
	if rf.sarif != "" {
		if _, err := writeFile(filepath.Dir(rf.sarif), filepath.Base(rf.sarif), func(w io.Writer) error {
			return report.WriteSARIF(w, ev, version.Version, rf.location)
		}); err != nil {
			fmt.Fprintln(stderr, "redfilade:", err)
			return exitError
		}
	}
	if rf.junit != "" {
		if _, err := writeFile(filepath.Dir(rf.junit), filepath.Base(rf.junit), func(w io.Writer) error {
			return report.WriteJUnit(w, "redfilade test "+level, []report.Case{{Name: label, Evidence: ev, WantExploited: false}})
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

// cmdTestRemote tests an MCP server reached over Streamable HTTP. Only a
// server on this machine is accepted until domain verification exists.
func cmdTestRemote(ctx context.Context, rawURL, tokenEnv, foreignEnv, level, protocol string, c common, rf reportFiles,
	stdin io.Reader, stdout, stderr io.Writer) int {
	u, err := neturl.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		fmt.Fprintln(stderr, "redfilade: --url must be an http or https URL without credentials in it")
		return exitError
	}
	proof := ""
	var hc *http.Client
	if isLoopback(u.Hostname()) {
		proof = "loopback: a server on this machine"
	} else {
		if u.Scheme != "https" {
			fmt.Fprintln(stderr, "redfilade: remote hosts must be tested over https")
			return exitError
		}
		v, err := domainVerifier()
		if err != nil {
			fmt.Fprintln(stderr, "redfilade:", err)
			return exitError
		}
		records, err := v.Records()
		if err != nil {
			fmt.Fprintln(stderr, "redfilade:", err)
			return exitError
		}
		hc, proof, err = v.RemoteClient(ctx, u.Hostname(), records, domain.RemoteOptions{Lookup: lookupNetIP, Allow: allowAddr, RootCAs: remoteRootCAs})
		if err != nil {
			fmt.Fprintf(stderr, "redfilade: %v\nRedfilade only tests remote servers on domains you have proven you control, at public addresses.\n", err)
			return exitError
		}
	}
	readEnv := func(name string) (string, bool) {
		if name == "" {
			return "", true
		}
		v := os.Getenv(name)
		if v == "" {
			fmt.Fprintf(stderr, "redfilade: environment variable %s is empty or not set\n", name)
			return "", false
		}
		return v, true
	}
	token, ok := readEnv(tokenEnv)
	if !ok {
		return exitError
	}
	foreign, ok := readEnv(foreignEnv)
	if !ok {
		return exitError
	}
	attacks := run.RemoteAttacks(level)
	if len(attacks) == 0 {
		fmt.Fprintf(stderr, "redfilade: level %s has no remote-safe attacks\n", level)
		return exitError
	}
	var ids []string
	for _, a := range attacks {
		ids = append(ids, a.ID)
	}
	p := consent.RemotePlan{URL: u.String(), Level: level, Attacks: ids, Requests: battery.RemoteRequestBudget(level), Proof: proof, Token: token != ""}
	if !approve(p, c, stdin, stdout, stderr) {
		return exitError
	}
	ev, err := run.Remote(ctx, run.RemoteOptions{URL: u.String(), Token: token, ForeignToken: foreign, HTTPClient: hc}, protocol, level,
		run.Options{Deadline: c.timeout, Version: version.Version, Commit: version.Commit})
	if err != nil {
		fmt.Fprintln(stderr, "redfilade:", err)
		return exitError
	}
	return finishTest(ev, u.Redacted(), level, c, rf, stdout, stderr)
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Seams for tests: how domains are verified and resolved, which addresses are
// acceptable, and which roots are trusted for TLS (nil = system roots).
var (
	domainVerifier = domain.NewVerifier
	lookupNetIP    func(ctx context.Context, host string) ([]netip.Addr, error)
	allowAddr      func(netip.Addr) bool
	remoteRootCAs  *x509.CertPool
)

func cmdDomain(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "list" && len(args) != 2) {
		fmt.Fprintln(stderr, "usage: redfilade domain challenge DOMAIN | domain verify DOMAIN | domain list")
		return exitError
	}
	v, err := domainVerifier()
	if err != nil {
		fmt.Fprintln(stderr, "redfilade:", err)
		return exitError
	}
	switch args[0] {
	case "challenge":
		r, err := v.Challenge(args[1])
		if err != nil {
			fmt.Fprintln(stderr, "redfilade:", err)
			return exitError
		}
		fmt.Fprintf(stdout, "Prove you control %s by publishing this token in ONE of these places:\n\n", r.Domain)
		fmt.Fprintf(stdout, "  DNS TXT record   %s%s\n                   value: %s\n                   (covers %s and all its subdomains)\n\n", domain.DNSPrefix, r.Domain, r.Token, r.Domain)
		fmt.Fprintf(stdout, "  HTTPS file       https://%s%s\n                   body:  %s\n                   (covers %s only)\n\n", r.Domain, domain.WellKnownPath, r.Token, r.Domain)
		fmt.Fprintf(stdout, "Then run: redfilade domain verify %s\n", r.Domain)
		return exitPass
	case "verify":
		r, err := v.Verify(ctx, args[1])
		if err != nil {
			fmt.Fprintln(stderr, "redfilade:", err)
			return exitFindings
		}
		fmt.Fprintf(stdout, "verified %s with a %s proof. Keep the proof published: it is checked again before every remote test.\n", r.Domain, r.Method)
		return exitPass
	case "list":
		rs, err := v.List()
		if err != nil {
			fmt.Fprintln(stderr, "redfilade:", err)
			return exitError
		}
		for _, r := range rs {
			state := "pending"
			if !r.VerifiedAt.IsZero() {
				state = "verified (" + r.Method + ", " + r.VerifiedAt.Format(time.RFC3339) + ")"
			}
			fmt.Fprintf(stdout, "%-40s %s\n", r.Domain, state)
		}
		return exitPass
	}
	fmt.Fprintln(stderr, "usage: redfilade domain challenge DOMAIN | domain verify DOMAIN | domain list")
	return exitError
}

// scenarioPlan is the consent screen for one build of a scenario; agent
// scenarios also name the model and where its data goes.
func scenarioPlan(m *scenario.Manifest, build string, tier sandbox.Tier, t *target, c common) consent.Plan {
	p := consent.FromManifest(m, build, tier, t.origin, t.digest, t.signature)
	if m.Kind == "agent" {
		p.Model = c.model
		trials := m.Agent.Trials
		if c.trials > 0 {
			trials = c.trials
		}
		p.Trials = trials
	}
	return p
}

// runScenario runs one build, through the agent engine for L3 scenarios.
func runScenario(ctx context.Context, m *scenario.Manifest, build string, o run.Options, c common) (*report.Evidence, error) {
	if m.Kind == "client" {
		return run.Client(ctx, m, build, o)
	}
	if m.Kind != "agent" {
		return run.Scenario(ctx, m, build, o)
	}
	if c.trials < 0 || c.trials > 50 {
		return nil, errors.New("--trials must be 0-50")
	}
	model, err := agent.New(c.model)
	if err != nil {
		return nil, err
	}
	return run.Agent(ctx, m, build, model, c.trials, o)
}

// cmdHostileServer runs Redfilade's hostile MCP server on stdin and stdout,
// for testing your own MCP client: add it to the client as a stdio server.
// Nothing but protocol messages is written to stdout; the session is saved
// to the log file when the client disconnects.
func cmdHostileServer(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hostile-server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	probes := fs.String("probes", "all", "comma-separated: elicitation, hidden_instruction, sampling, or all")
	logFile := fs.String("log", "redfilade-hostile-session.jsonl", "where to save the session for client-report")
	idle := fs.Duration("idle", 10*time.Minute, "end the session after this long without messages")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	list, err := hostile.SortedProbes(strings.Split(*probes, ","))
	if err != nil {
		fmt.Fprintln(stderr, "redfilade:", err)
		return exitError
	}
	rec := mcp.NewRecorder(mcp.DefaultMaxMessageBytes)
	fmt.Fprintf(stderr, "redfilade hostile server: probes %s; session log %s\n", strings.Join(list, ", "), *logFile)
	serr := hostile.Serve(ctx, stdin, stdout, hostile.Options{Probes: list, Recorder: rec, Idle: *idle})
	session := map[string]any{"schema": "redfilade.hostile-session/v1", "probes": list, "frames": rec.Frames()}
	if _, err := writeFile(filepath.Dir(*logFile), filepath.Base(*logFile), func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", " ")
		return enc.Encode(session)
	}); err != nil {
		fmt.Fprintln(stderr, "redfilade:", err)
		return exitError
	}
	if serr != nil {
		fmt.Fprintln(stderr, "redfilade:", serr)
		return exitError
	}
	return exitPass
}

// cmdClientReport judges a hostile-server session log.
func cmdClientReport(args []string, stdout, stderr io.Writer) int {
	file, rest := splitPositional(args)
	fs := flag.NewFlagSet("client-report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sarif := fs.String("sarif", "", "write SARIF 2.1.0 to this file")
	out := fs.String("out", "redfilade-results", "directory for the evidence file")
	if err := fs.Parse(rest); err != nil || file == "" {
		fmt.Fprintln(stderr, "usage: redfilade client-report FILE [--sarif FILE] [--out DIR]")
		return exitError
	}
	b, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintln(stderr, "redfilade:", err)
		return exitError
	}
	var session struct {
		Schema string      `json:"schema"`
		Probes []string    `json:"probes"`
		Frames []mcp.Frame `json:"frames"`
	}
	if err := json.Unmarshal(b, &session); err != nil || session.Schema != "redfilade.hostile-session/v1" {
		fmt.Fprintln(stderr, "redfilade: not a hostile-server session log")
		return exitError
	}
	probes, err := hostile.SortedProbes(session.Probes)
	if err != nil {
		fmt.Fprintln(stderr, "redfilade:", err)
		return exitError
	}
	ev := run.ClientReport(session.Frames, probes, version.Version)
	summary(stdout, "your client [L4]", ev)
	if _, err := writeFile(*out, "evidence-client-L4.json", func(w io.Writer) error { return report.WriteEvidence(w, ev) }); err != nil {
		fmt.Fprintln(stderr, "redfilade:", err)
		return exitError
	}
	if *sarif != "" {
		if _, err := writeFile(filepath.Dir(*sarif), filepath.Base(*sarif), func(w io.Writer) error {
			return report.WriteSARIF(w, ev, version.Version, "README.md")
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
