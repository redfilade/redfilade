// Package run executes one target or scenario build end to end:
// world -> cell -> MCP connect -> exploit -> stop -> diff -> oracle -> evidence.
package run

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/redfilade/redfilade/internal/battery"
	"github.com/redfilade/redfilade/internal/mcp"
	"github.com/redfilade/redfilade/internal/oracle"
	"github.com/redfilade/redfilade/internal/report"
	"github.com/redfilade/redfilade/internal/sandbox"
	"github.com/redfilade/redfilade/internal/scenario"
	"github.com/redfilade/redfilade/internal/world"
)

// Options configure a run.
type Options struct {
	Runner   sandbox.Runner
	Tier     sandbox.Tier
	Deadline time.Duration // whole-run limit; default 120s
	Version  string
	Commit   string
	Pull     string // image pull policy for builder images ("missing"); twins use "never"
}

func (o Options) deadline() time.Duration {
	if o.Deadline <= 0 {
		return 120 * time.Second
	}
	return o.Deadline
}

// NewRunID returns a random run identifier.
func NewRunID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Scenario runs one build ("vulnerable" or "secure") of a scenario.
func Scenario(ctx context.Context, m *scenario.Manifest, build string, o Options) (*report.Evidence, error) {
	b := m.Builds.Secure
	if build == "vulnerable" {
		b = m.Builds.Vulnerable
	} else if build != "secure" {
		return nil, fmt.Errorf("unknown build %q", build)
	}
	w, err := world.Build(m)
	if err != nil {
		return nil, err
	}
	defer w.Close()
	subject := report.Subject{Mode: "range", ScenarioID: m.ID, Build: build, Image: b.Image, Protocol: m.Protocol, Level: m.Level, Family: m.Family}
	steps := func(ctx context.Context, c *mcp.Client, tools []mcp.Tool, env battery.Env) error {
		for i, s := range m.Exploit {
			if s.Battery != "" {
				a, ok := battery.Get(s.Battery)
				if !ok {
					return fmt.Errorf("step %d: unknown battery attack %q", i+1, s.Battery)
				}
				if err := a.Run(ctx, c, tools, env); err != nil {
					return fmt.Errorf("step %d (%s): %w", i+1, s.Battery, err)
				}
				continue
			}
			args, _ := renderValue(s.Arguments, w.Canaries).(map[string]any)
			if _, err := c.CallTool(ctx, s.Call, args); err != nil {
				return fmt.Errorf("step %d (%s): %w", i+1, s.Call, err)
			}
		}
		return nil
	}
	return execute(ctx, o, w, subject, b.Cmd, m.Needs.Network, m.Oracle.Checks, m.Oracle.Match, "never", steps)
}

// Target runs a level's battery against a builder's own server image.
// Levels are cumulative (L2 includes L1).
func Target(ctx context.Context, image string, cmd []string, protocol, level string, o Options) (*report.Evidence, error) {
	attacks := battery.ForLevel(level)
	if len(attacks) == 0 {
		return nil, fmt.Errorf("no battery attacks exist for %s yet", level)
	}
	// A builder's server gets only Redfilade's synthetic world: canary files
	// and variables it must never expose, and nothing of the user's.
	synth := &scenario.Manifest{Needs: scenario.Needs{Network: "none"}}
	var checks []scenario.Check
	seen := map[string]bool{}
	for _, a := range attacks {
		synth.World = append(synth.World, a.World...)
		synth.Needs.Env = append(synth.Needs.Env, a.Env...)
		if a.Network == "sink" {
			synth.Needs.Network = "sink"
		}
		for _, c := range a.Checks {
			key := c.Fact + "|" + c.Canary + "|" + c.Path
			if !seen[key] {
				seen[key] = true
				checks = append(checks, c)
			}
		}
	}
	w, err := world.Build(synth)
	if err != nil {
		return nil, err
	}
	defer w.Close()
	subject := report.Subject{Mode: "test", Image: image, Protocol: protocol, Level: level}
	steps := func(ctx context.Context, c *mcp.Client, tools []mcp.Tool, env battery.Env) error {
		for _, a := range attacks {
			if err := a.Run(ctx, c, tools, env); err != nil {
				return fmt.Errorf("%s: %w", a.ID, err)
			}
		}
		return nil
	}
	pull := o.Pull
	if pull == "" {
		pull = "missing"
	}
	return execute(ctx, o, w, subject, cmd, synth.Needs.Network, checks, "any", pull, steps)
}

type stepFunc func(ctx context.Context, c *mcp.Client, tools []mcp.Tool, env battery.Env) error

func execute(ctx context.Context, o Options, w *world.World, subject report.Subject, cmd []string, network string,
	checks []scenario.Check, match, pull string, steps stepFunc) (*report.Evidence, error) {

	ctx, cancel := context.WithTimeout(ctx, o.deadline())
	defer cancel()
	runID := NewRunID()
	ev := &report.Evidence{
		Schema:    report.SchemaEvidence,
		RunID:     runID,
		Tool:      report.Tool{Name: "redfilade", Version: o.Version, Commit: o.Commit},
		Subject:   subject,
		Isolation: string(o.Tier),
		StartedAt: time.Now().UTC(),
		Signature: report.Unsigned,
	}
	net := "none"
	env := battery.Env{Canaries: w.Canaries}
	var sink *sandbox.Sink
	if network == "sink" {
		logDir := filepath.Join(w.Root, "sink")
		if err := os.Mkdir(logDir, 0o777); err != nil {
			return nil, err
		}
		_ = os.Chmod(logDir, 0o777)
		var err error
		sink, err = o.Runner.StartSink(ctx, runID, logDir, w.Canaries[scenario.SinkCanary], o.Tier)
		if err != nil {
			return nil, fmt.Errorf("start egress sink: %w", err)
		}
		defer sink.Stop()
		net = sink.Network
		env.SinkURL = "http://" + sandbox.SinkHost + ":" + sandbox.SinkPort
	}
	cell, err := o.Runner.Start(ctx, sandbox.Spec{
		Name: "redfilade-" + runID, Image: subject.Image, Cmd: cmd, WorldDir: w.Dir,
		Network: net, Env: w.Env, Tier: o.Tier, Pull: pull,
	})
	if err != nil {
		return nil, fmt.Errorf("start cell: %w", err)
	}
	proto := mcp.Protocol2026
	if subject.Protocol == mcp.Protocol2025 {
		proto = mcp.Protocol2025
	}
	client := mcp.New(cell.Stdout, cell.Stdin, mcp.Options{Protocol: proto, ClientVersion: o.Version})

	completed := false
	func() {
		if _, err := client.Connect(ctx); err != nil {
			ev.Errors = append(ev.Errors, "connect: "+err.Error())
			return
		}
		tools, err := client.ListTools(ctx)
		if err != nil {
			ev.Errors = append(ev.Errors, "tools/list: "+err.Error())
			return
		}
		if err := steps(ctx, client, tools, env); err != nil {
			ev.Errors = append(ev.Errors, err.Error())
			return
		}
		completed = true
	}()
	cell.Stop()
	if !completed {
		if s := cell.Stderr(); s != "" {
			ev.Errors = append(ev.Errors, "cell stderr: "+w.Redact(report.Clean(s, 800)))
		}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		ev.Errors = append(ev.Errors, "run deadline exceeded")
	}

	changes, err := w.Diff()
	if err != nil {
		ev.Errors = append(ev.Errors, "world diff: "+err.Error())
	}
	var egress []oracle.Egress
	if sink != nil {
		events, err := sink.Events()
		if err != nil {
			ev.Errors = append(ev.Errors, "sink log: "+err.Error())
		}
		for _, e := range events {
			egress = append(egress, oracle.Egress(e))
		}
		ev.Egress = make([]oracle.Egress, len(egress))
		for i, e := range egress {
			ev.Egress[i] = oracle.Egress{Method: report.Clean(w.Redact(e.Method), 16), Host: report.Clean(w.Redact(e.Host), 256),
				Path: report.Clean(w.Redact(e.Path), 512), Query: report.Clean(w.Redact(e.Query), 512), Body: report.Clean(w.Redact(e.Body), 512)}
		}
	}
	frames := client.Recorder().Frames()
	ev.Oracle = oracle.Evaluate(oracle.Input{
		Frames: frames, Egress: egress, Changes: changes, Canaries: w.Canaries,
		Checks: checks, Match: match, Completed: completed, Network: network,
	})
	ev.WorldChanges = changes
	if ev.WorldChanges == nil {
		ev.WorldChanges = []world.Change{}
	}
	ev.Frames = report.RedactFrames(frames, w.Canaries)
	for i := range ev.Errors {
		ev.Errors[i] = w.Redact(ev.Errors[i])
	}
	ev.FinishedAt = time.Now().UTC()
	return ev, nil
}

// renderValue replaces canary placeholders in every string of an argument tree.
func renderValue(v any, canaries map[string]string) any {
	switch t := v.(type) {
	case string:
		return scenario.Render(t, canaries)
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = renderValue(x, canaries)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = renderValue(x, canaries)
		}
		return out
	default:
		return v
	}
}
