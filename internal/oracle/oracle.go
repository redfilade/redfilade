// Package oracle decides what happened in a run from observed facts only
// (ADR-0006, ADR-0013). It never trusts what the target says about itself.
package oracle

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/redfilade/redfilade/internal/mcp"
	"github.com/redfilade/redfilade/internal/rules"
	"github.com/redfilade/redfilade/internal/scenario"
	"github.com/redfilade/redfilade/internal/world"
)

// Verdicts.
const (
	Exploited    = "exploited"     // the declared facts were observed
	NotExploited = "not_exploited" // the run completed and no declared fact was observed
	Inconclusive = "inconclusive"  // the run did not complete, so absence proves nothing
)

// Finding is one observed fact.
type Finding struct {
	Fact     string `json:"fact"`
	Detector string `json:"detector,omitempty"`
	Canary   string `json:"canary,omitempty"`
	Path     string `json:"path,omitempty"`
	FrameSeq int    `json:"frame_seq,omitempty"`
	Excerpt  string `json:"excerpt,omitempty"` // redacted and truncated
}

// Result is the oracle's judgement.
type Result struct {
	Verdict     string    `json:"verdict"`
	Match       string    `json:"match"`
	Findings    []Finding `json:"findings"`
	NotObserved []string  `json:"not_observed"`
	Reason      string    `json:"reason,omitempty"`
}

// Egress is one request recorded by the egress sink.
type Egress struct {
	Method string `json:"method"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	Query  string `json:"query"`
	Body   string `json:"body"`
}

// Input is everything the oracle may look at.
type Input struct {
	Frames    []mcp.Frame
	Egress    []Egress
	Changes   []world.Change
	Canaries  map[string]string // name -> value
	Checks    []scenario.Check
	Match     string // "any" or "all"
	Completed bool   // every exploit step ran
	Network   string // "none" or "sink"
}

// detector is a named, linear-time (RE2) pattern for runtime internals.
type detector struct {
	name string
	re   *regexp.Regexp
}

// Detectors for internals_leaked. Go's regexp is RE2, so hostile output can
// not trigger catastrophic backtracking.
var detectors = []detector{
	{"python-traceback", regexp.MustCompile(`Traceback \(most recent call last\)`)},
	{"go-panic", regexp.MustCompile(`goroutine \d+ \[[a-z ]+\]:|panic: .{0,200}\n?\s*goroutine`)},
	{"go-stack-frame", regexp.MustCompile(`\n\s*/[\w./-]+\.go:\d+`)},
	{"node-stack-frame", regexp.MustCompile(`\bat [\w$.<> ]+ \((?:/|[A-Za-z]:\\)[^)\s]+:\d+:\d+\)`)},
	{"java-stack-frame", regexp.MustCompile(`\bat [\w$.]+\([\w$]+\.java:\d+\)`)},
	{"source-path", regexp.MustCompile(`(?:/home|/root|/usr/src|/app|/srv|/opt|/workspace)/[\w./-]+\.(?:py|go|js|mjs|ts|java|rb|rs|cs|php)\b`)},
	{"windows-path", regexp.MustCompile(`[A-Za-z]:\\(?:Users|Program Files|inetpub)\\`)},
	{"connection-string", regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://[^\s"'<>]{3,}`)},
}

// secretDetectors find well-known credential formats in replies. Patterns are
// specific on purpose: a generic "password=" rule would flag secure servers.
var secretDetectors = []detector{
	{"redfilade-canary", regexp.MustCompile(`CANARY_[A-Z0-9_]+_[A-Z2-7]{26}`)},
	{"aws-access-key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"github-token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)},
	{"slack-token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`)},
	{"private-key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},
}

// fileDetectors find the contents of sensitive system files in replies.
var fileDetectors = []detector{
	{"etc-passwd", regexp.MustCompile(`(?m)^root:[^:\n]*:0:0:`)},
	{"private-key-file", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)},
	{"process-environ", regexp.MustCompile(`PATH=/[^\s\x00]*\x00|HOSTNAME=[^\s\x00]+\x00`)},
}

// NotObservable lists what this runner cannot see; reports always show it.
func NotObservable(network string) []string {
	out := []string{
		"file reads inside the cell (needs host-side eBPF, ADR-0006)",
		"process execution inside the cell (needs host-side eBPF, ADR-0006)",
	}
	if network == "none" || network == "" {
		out = append(out, "network attempts (the cell has no network, so none could succeed)")
	} else {
		out = append(out, "network traffic to destinations other than the egress sink (the internal network has no route out)")
	}
	return out
}

// Evaluate judges a run.
func Evaluate(in Input) Result {
	match := in.Match
	if match == "" {
		match = "any"
	}
	res := Result{Match: match, NotObserved: NotObservable(in.Network), Findings: []Finding{}}
	strs := serverStrings(in.Frames)
	redact := func(s string) string {
		for name, v := range in.Canaries {
			s = strings.ReplaceAll(s, v, "[canary:"+name+"]")
		}
		return s
	}

	fired := 0
	for _, c := range in.Checks {
		var got []Finding
		switch c.Fact {
		case "canary_leaked":
			v := in.Canaries[c.Canary]
			for _, s := range strs {
				if v != "" && strings.Contains(s.text, v) {
					got = append(got, Finding{Fact: c.Fact, Canary: c.Canary, FrameSeq: s.seq, Excerpt: excerpt(redact(s.text), "[canary:"+c.Canary+"]")})
					break
				}
			}
		case "world_file_changed":
			for _, ch := range in.Changes {
				if ch.Path == c.Path && ch.Change != "created" {
					got = append(got, Finding{Fact: c.Fact, Path: ch.Path, Excerpt: ch.Change})
				}
			}
		case "egress_reached_sink":
			for _, e := range in.Egress {
				got = append(got, Finding{Fact: c.Fact, Excerpt: redact(e.Method + " " + e.Host + e.Path + query(e.Query))})
				break
			}
		case "canary_egressed":
			v := in.Canaries[c.Canary]
			for _, e := range in.Egress {
				if v != "" && strings.Contains(e.Host+e.Path+"?"+e.Query+"\n"+e.Body, v) {
					got = append(got, Finding{Fact: c.Fact, Canary: c.Canary, Excerpt: redact(e.Method + " " + e.Host + e.Path + query(e.Query))})
					break
				}
			}
		case "secret_pattern_leaked", "sensitive_file_read":
			set := secretDetectors
			if c.Fact == "sensitive_file_read" {
				set = fileDetectors
			}
			seen := map[string]bool{}
			for _, s := range strs {
				for _, d := range set {
					if seen[d.name] {
						continue
					}
					if loc := d.re.FindStringIndex(s.text); loc != nil {
						seen[d.name] = true
						got = append(got, Finding{Fact: c.Fact, Detector: d.name, FrameSeq: s.seq, Excerpt: excerpt(redact(s.text), redact(s.text[loc[0]:loc[1]]))})
					}
				}
			}
		case "tool_metadata_flagged", "output_injection_flagged":
			got = ruleFindings(c.Fact, in.Frames, redact, &res)
		case "internals_leaked":
			seen := map[string]bool{}
			for _, s := range strs {
				for _, d := range detectors {
					if seen[d.name] {
						continue
					}
					if loc := d.re.FindStringIndex(s.text); loc != nil {
						seen[d.name] = true
						got = append(got, Finding{Fact: c.Fact, Detector: d.name, FrameSeq: s.seq, Excerpt: excerpt(redact(s.text), redact(s.text[loc[0]:loc[1]]))})
					}
				}
			}
		}
		if len(got) > 0 {
			fired++
			res.Findings = append(res.Findings, got...)
		}
	}
	sort.SliceStable(res.Findings, func(i, j int) bool { return res.Findings[i].FrameSeq < res.Findings[j].FrameSeq })

	exploited := fired > 0
	if match == "all" {
		exploited = len(in.Checks) > 0 && fired == len(in.Checks)
	}
	switch {
	case exploited:
		res.Verdict = Exploited
	case !in.Completed:
		res.Verdict = Inconclusive
		res.Reason = "the run did not complete, so the absence of findings proves nothing"
	default:
		res.Verdict = NotExploited
	}
	return res
}

// RuleScanBudget bounds how much text one evaluation feeds to the detection
// rules, so a hostile server cannot make the oracle slow by sending a lot.
const RuleScanBudget = 1 << 20

// outputRules are the rules that make sense for what a tool returns: text
// aimed at the model, not descriptions of what code does.
var outputRules = []string{"prompt_injection", "coercive_injection", "script_injection"}

// ruleFindings applies the bundled detection rules to tool metadata
// (tools/list results) or tool output (tools/call results).
func ruleFindings(fact string, frames []mcp.Frame, redact func(string) string, res *Result) []Finding {
	set, err := rules.Cisco()
	if err != nil {
		res.NotObserved = append(res.NotObserved, "detection rules failed to load: "+err.Error())
		return nil
	}
	if fact == "output_injection_flagged" {
		set = set.Only(outputRules...)
	}
	budget := RuleScanBudget
	seen := map[string]bool{}
	var got []Finding
	for _, f := range frames {
		if f.Direction != mcp.DirServerToClient {
			continue
		}
		var msg struct {
			Result struct {
				Tools   []map[string]any `json:"tools"`
				Content []any            `json:"content"`
			} `json:"result"`
		}
		if json.Unmarshal(f.Raw, &msg) != nil {
			continue
		}
		type field struct{ where, text string }
		var fields []field
		if fact == "tool_metadata_flagged" {
			for _, t := range msg.Result.Tools {
				name, _ := t["name"].(string)
				if d, ok := t["description"].(string); ok {
					fields = append(fields, field{"tool " + name + " description", d})
				}
				var params []string
				walk(t["inputSchema"], &params, 0)
				if len(params) > 0 {
					fields = append(fields, field{"tool " + name + " parameters", strings.Join(params, "\n")})
				}
			}
		} else {
			var parts []string
			walk(msg.Result.Content, &parts, 0)
			if len(parts) > 0 {
				fields = append(fields, field{"tool output", strings.Join(parts, "\n")})
			}
		}
		for _, fl := range fields {
			text := fl.text
			if len(text) > budget {
				text = text[:budget]
			}
			budget -= len(text)
			for _, h := range set.Match(text) {
				key := h.Rule + "|" + fl.where
				if seen[key] {
					continue
				}
				seen[key] = true
				x := redact(text)
				if h.Start >= 0 && h.End <= len(text) {
					x = excerpt(redact(text), redact(text[h.Start:h.End]))
				}
				got = append(got, Finding{Fact: fact, Detector: "cisco:" + h.Rule, Path: fl.where, FrameSeq: f.Seq, Excerpt: x})
			}
			if budget <= 0 {
				res.NotObserved = append(res.NotObserved, "detection rules stopped after 1 MiB of server text in this run")
				return got
			}
		}
	}
	return got
}

type located struct {
	seq  int
	text string
}

// serverStrings returns every string value the target sent, decoded from
// JSON so escapes cannot hide a match. Non-JSON frames are used as-is.
func serverStrings(frames []mcp.Frame) []located {
	var out []located
	for _, f := range frames {
		if f.Direction != mcp.DirServerToClient {
			continue
		}
		var v any
		if err := json.Unmarshal(f.Raw, &v); err != nil {
			out = append(out, located{f.Seq, string(f.Raw)})
			continue
		}
		var parts []string
		walk(v, &parts, 0)
		out = append(out, located{f.Seq, strings.Join(parts, "\n")})
	}
	return out
}

func walk(v any, out *[]string, depth int) {
	if depth > 64 {
		return
	}
	switch t := v.(type) {
	case string:
		*out = append(*out, t)
		// Tools often return JSON inside a text block; look inside it too.
		if depth < 32 && len(t) > 1 && (t[0] == '{' || t[0] == '[') {
			var inner any
			if json.Unmarshal([]byte(t), &inner) == nil {
				walk(inner, out, depth+1)
			}
		}
	case []any:
		for _, x := range t {
			walk(x, out, depth+1)
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			*out = append(*out, k)
			walk(t[k], out, depth+1)
		}
	}
}

func query(q string) string {
	if q == "" {
		return ""
	}
	return "?" + q
}

// excerpt returns up to ~160 characters around needle.
func excerpt(s, needle string) string {
	i := strings.Index(s, needle)
	if i < 0 {
		i = 0
	}
	start, end := i-60, i+len(needle)+60
	if start < 0 {
		start = 0
	}
	if end > len(s) {
		end = len(s)
	}
	out := s[start:end]
	if start > 0 {
		out = "…" + out
	}
	if end < len(s) {
		out += "…"
	}
	return out
}
