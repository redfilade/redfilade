// Package report writes the evidence bundle, SARIF and JUnit outputs.
//
// Everything that came from a target is hostile: before it reaches a report
// it is redacted (canaries), stripped of control and bidi characters, and
// length-capped. Raw target output never appears in titles or rule names.
package report

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/redfilade/redfilade/internal/mcp"
	"github.com/redfilade/redfilade/internal/oracle"
	"github.com/redfilade/redfilade/internal/world"
)

// SchemaEvidence identifies the evidence bundle format.
const SchemaEvidence = "redfilade.evidence/v1"

// Evidence is the full record of one run.
type Evidence struct {
	Schema       string             `json:"schema"`
	RunID        string             `json:"run_id"`
	Tool         Tool               `json:"tool"`
	Subject      Subject            `json:"subject"`
	Isolation    string             `json:"isolation"`
	StartedAt    time.Time          `json:"started_at"`
	FinishedAt   time.Time          `json:"finished_at"`
	Oracle       oracle.Result      `json:"oracle"`
	WorldChanges []world.Change     `json:"world_changes"`
	Egress       []oracle.Egress    `json:"egress,omitempty"`
	HTTP         []mcp.HTTPExchange `json:"http,omitempty"`
	Agent        *AgentResult       `json:"agent,omitempty"` // L3 runs
	Frames       []mcp.Frame        `json:"frames"`
	Errors       []string           `json:"errors,omitempty"`
	Signature    Signature          `json:"signature"`
}

// AgentResult summarises an L3 run over several trials.
type AgentResult struct {
	Model       string            `json:"model"`
	Task        string            `json:"task"`
	Trials      int               `json:"trials"`
	Completed   int               `json:"completed"` // trials that ran to the end
	Exploited   int               `json:"exploited"`
	Rate        float64           `json:"rate"`        // exploited / completed
	Interval95  [2]float64        `json:"interval_95"` // Wilson score interval
	Transcripts []json.RawMessage `json:"transcripts"` // redacted, one per trial
}

// Tool identifies the Redfilade build that produced the evidence.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// Subject is what was tested.
type Subject struct {
	Mode       string `json:"mode"` // "range" or "test"
	ScenarioID string `json:"scenario_id,omitempty"`
	Build      string `json:"build,omitempty"`
	Image      string `json:"image,omitempty"`
	URL        string `json:"url,omitempty"` // remote targets
	Protocol   string `json:"protocol"`
	Level      string `json:"level"`
	Family     string `json:"family,omitempty"`
}

// Signature records whether and how the evidence was signed.
type Signature struct {
	Status string `json:"status"` // "unsigned" or "signed"
	Reason string `json:"reason,omitempty"`
}

// Unsigned is the signature block for local and untrusted-CI runs.
var Unsigned = Signature{Status: "unsigned", Reason: "local or untrusted-CI run; only the release workflow signs evidence (ADR-0007)"}

// Clean makes target-controlled text safe for any report or terminal.
func Clean(s string, max int) string {
	s = strings.ToValidUTF8(s, "�")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(' ')
		case unicode.IsControl(r), r == 0x2028, r == 0x2029,
			r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r == 0x200B, r == 0x200E, r == 0x200F, r == 0xFEFF:
			// control, line separators, bidi overrides, zero-width: dropped
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	if utf8.RuneCountInString(out) > max {
		rs := []rune(out)
		out = string(rs[:max]) + "…"
	}
	return out
}

// RedactFrames returns frames with canary values replaced by their names.
func RedactFrames(frames []mcp.Frame, canaries map[string]string) []mcp.Frame {
	out := make([]mcp.Frame, len(frames))
	for i, f := range frames {
		raw := string(f.Raw)
		for name, v := range canaries {
			raw = strings.ReplaceAll(raw, v, "[canary:"+name+"]")
		}
		f.Raw = json.RawMessage(raw)
		if !json.Valid(f.Raw) {
			q, _ := json.Marshal(raw)
			f.Raw = q
		}
		out[i] = f
	}
	return out
}

// WriteEvidence writes the bundle as indented JSON.
func WriteEvidence(w io.Writer, e *Evidence) error {
	for i := range e.Oracle.Findings {
		e.Oracle.Findings[i].Excerpt = Clean(e.Oracle.Findings[i].Excerpt, 400)
	}
	for i := range e.Errors {
		e.Errors[i] = Clean(e.Errors[i], 400)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(true)
	return enc.Encode(e)
}

// --- SARIF 2.1.0 -----------------------------------------------------------

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	ShortDescription sarifText `json:"shortDescription"`
	Help             sarifText `json:"help"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	Physical sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	Artifact sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// Rule metadata is written by us, never derived from target output.
var rules = map[string]sarifRule{
	"canary_leaked": {ID: "RF-CANARY-LEAK", Name: "SecretLeakedToClient",
		ShortDescription: sarifText{"A planted secret was returned to the client"},
		Help:             sarifText{"The target returned a secret it should never expose (a Redfilade canary). Remove secrets from responses and error messages."}},
	"internals_leaked": {ID: "RF-INTERNALS-LEAK", Name: "InternalsInResponse",
		ShortDescription: sarifText{"Stack traces, source paths or connection strings in responses"},
		Help:             sarifText{"Return a generic error to the client and log details on the server only."}},
	"world_file_changed": {ID: "RF-WORLD-TAMPER", Name: "UnauthorisedFileChange",
		ShortDescription: sarifText{"A protected file was modified"},
		Help:             sarifText{"The target changed a file outside the area it is allowed to write. Resolve paths and reject anything outside the allowed directory."}},
	"secret_pattern_leaked": {ID: "RF-SECRET-PATTERN", Name: "CredentialInResponse",
		ShortDescription: sarifText{"A credential-shaped value was returned to the client"},
		Help:             sarifText{"Never return environment variables, keys or tokens in tool output."}},
	"sensitive_file_read": {ID: "RF-FILE-READ", Name: "SensitiveFileRead",
		ShortDescription: sarifText{"The contents of a sensitive file were returned"},
		Help:             sarifText{"Resolve requested paths and reject anything outside the allowed directory, including encoded and absolute paths."}},
	"egress_reached_sink": {ID: "RF-SSRF", Name: "ServerSideRequestForgery",
		ShortDescription: sarifText{"The server fetched an attacker-chosen URL"},
		Help:             sarifText{"Allow-list the hosts a tool may contact and block private, link-local and metadata addresses."}},
	"canary_egressed": {ID: "RF-EXFILTRATION", Name: "SecretSentToNetwork",
		ShortDescription: sarifText{"A planted secret was sent to an external address"},
		Help:             sarifText{"The server sent a secret to an attacker-controlled destination."}},
	"tool_metadata_flagged": {ID: "RF-TOOL-POISONING", Name: "PoisonedToolMetadata",
		ShortDescription: sarifText{"A tool description or parameter carries hidden instructions or hidden behaviour"},
		Help:             sarifText{"Tool descriptions are read by the AI model. Describe only what the tool does; never include instructions to the model, hidden actions or requests for secrets. Detection rules: Cisco MCP Scanner (Apache-2.0)."}},
	"client_followed_hidden_instruction": {ID: "RF-CLIENT-HIDDEN-TEXT", Name: "ClientFollowedHiddenInstruction",
		ShortDescription: sarifText{"The client acted on instructions hidden in invisible characters in a tool description"},
		Help:             sarifText{"Strip or visibly render Unicode tag characters and other invisible text in tool metadata before showing it to a model or a user."}},
	"client_answered_elicitation": {ID: "RF-CLIENT-ELICITATION", Name: "ClientAnsweredPhishingElicitation",
		ShortDescription: sarifText{"The client returned data for a server request asking for the user's password"},
		Help:             sarifText{"Show elicitation requests clearly as coming from the server, never auto-fill them, and warn on requests for passwords or other credentials."}},
	"client_answered_sampling": {ID: "RF-CLIENT-SAMPLING", Name: "ClientRanServerSampling",
		ShortDescription: sarifText{"The client ran a model completion a server asked for, and returned it"},
		Help:             sarifText{"Require the user to review and approve every sampling request and its result, and limit what context it may include."}},
	"client_leaked_canary": {ID: "RF-CLIENT-LEAK", Name: "ClientLeakedSecret",
		ShortDescription: sarifText{"A secret from the client's environment reached the hostile server"},
		Help:             sarifText{"Never send credentials or local secrets to a server without explicit user consent."}},
	"agent_leaked_canary": {ID: "RF-AGENT-HIJACK", Name: "AgentHijackedToLeakSecret",
		ShortDescription: sarifText{"An AI agent was steered by tool data into sending a secret, and the server carried it out"},
		Help:             sarifText{"Treat content from tools as untrusted data. On the server, require confirmation or an allow-list for actions that send data out (recipients, URLs), and never let tool output alone authorise them."}},
	"auth_bypassed": {ID: "RF-AUTH-BYPASS", Name: "AuthenticationBypassed",
		ShortDescription: sarifText{"A request without a valid token for this server was served"},
		Help:             sarifText{"Require a bearer token on every request, verify its signature and expiry, and reject tokens whose audience is not this server (RFC 8707, MCP authorization). Return 401 with WWW-Authenticate."}},
	"rate_limit_missing": {ID: "RF-NO-RATE-LIMIT", Name: "NoRateLimit",
		ShortDescription: sarifText{"A burst of requests was served without any rate limiting"},
		Help:             sarifText{"Limit requests per client and per token, and answer excess requests with 429 and Retry-After."}},
	"header_mismatch_accepted": {ID: "RF-HEADER-MISMATCH", Name: "RoutingHeaderMismatchAccepted",
		ShortDescription: sarifText{"A request whose Mcp-Method or Mcp-Name header disagrees with its body was served"},
		Help:             sarifText{"Gateways route and authorise on these headers. Reject any request whose headers do not match the JSON-RPC body (MCP 2026-07-28, Streamable HTTP)."}},
	"output_injection_flagged": {ID: "RF-OUTPUT-INJECTION", Name: "InjectionInToolOutput",
		ShortDescription: sarifText{"Tool output carries prompt-injection or hidden-script text"},
		Help:             sarifText{"Treat data a tool returns as untrusted. Strip or neutralise instructions, markup and terminal escape codes before returning it to the model. Detection rules: Cisco MCP Scanner (Apache-2.0)."}},
}

// WriteSARIF writes findings as SARIF 2.1.0. location is the repository path
// results are attached to (for example the server's entry point or manifest).
func WriteSARIF(w io.Writer, e *Evidence, version, location string) error {
	if location == "" {
		location = "README.md"
	}
	used := map[string]bool{}
	var results []sarifResult
	for _, f := range e.Oracle.Findings {
		r, ok := rules[f.Fact]
		if !ok {
			continue
		}
		used[f.Fact] = true
		msg := r.ShortDescription.Text
		if f.Detector != "" {
			msg += " (" + f.Detector + ")"
		}
		if f.Canary != "" {
			msg += " (canary " + f.Canary + ")"
		}
		if f.Excerpt != "" {
			msg += ". Excerpt: " + Clean(f.Excerpt, 300)
		}
		target := "image " + Clean(e.Subject.Image, 200)
		if e.Subject.URL != "" {
			target = "URL " + Clean(e.Subject.URL, 200)
		}
		msg += fmt.Sprintf(". Level %s, %s.", e.Subject.Level, target)
		results = append(results, sarifResult{RuleID: r.ID, Level: "error", Message: sarifText{msg},
			Locations: []sarifLocation{{sarifPhysical{sarifArtifact{location}}}}})
	}
	var rs []sarifRule
	facts := make([]string, 0, len(rules))
	for f := range rules {
		facts = append(facts, f)
	}
	sort.Strings(facts)
	for _, fact := range facts {
		if used[fact] {
			rs = append(rs, rules[fact])
		}
	}
	if results == nil {
		results = []sarifResult{}
	}
	if rs == nil {
		rs = []sarifRule{}
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{sarifDriver{Name: "Redfilade", Version: version, InformationURI: "https://github.com/redfilade/redfilade", Rules: rs}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(true)
	return enc.Encode(log)
}

// --- JUnit -----------------------------------------------------------------

type junitSuites struct {
	XMLName xml.Name     `xml:"testsuites"`
	Suites  []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Errors   int         `xml:"errors,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Error     *junitFailure `xml:"error,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

// Case is one pass/fail expectation for JUnit.
type Case struct {
	Name     string
	Evidence *Evidence
	// WantExploited is true when this case expects the attack to succeed
	// (the vulnerable twin in a range gate).
	WantExploited bool
}

// WriteJUnit writes cases as JUnit XML. encoding/xml escapes all text.
func WriteJUnit(w io.Writer, suite string, cases []Case) error {
	s := junitSuite{Name: Clean(suite, 120)}
	for _, c := range cases {
		jc := junitCase{Name: Clean(c.Name, 200), ClassName: "redfilade." + Clean(c.Evidence.Subject.Level, 8)}
		v := c.Evidence.Oracle.Verdict
		switch {
		case v == oracle.Inconclusive:
			jc.Error = &junitFailure{Message: "inconclusive", Text: Clean(c.Evidence.Oracle.Reason+" "+strings.Join(c.Evidence.Errors, "; "), 800)}
			s.Errors++
		case (v == oracle.Exploited) != c.WantExploited:
			want := "not exploited"
			if c.WantExploited {
				want = "exploited"
			}
			var lines []string
			for _, f := range c.Evidence.Oracle.Findings {
				lines = append(lines, f.Fact+" "+f.Detector+" "+Clean(f.Excerpt, 200))
			}
			jc.Failure = &junitFailure{Message: "verdict " + v + ", expected " + want, Text: Clean(strings.Join(lines, " | "), 1500)}
			s.Failures++
		}
		s.Cases = append(s.Cases, jc)
		s.Tests++
	}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	return enc.Encode(junitSuites{Suites: []junitSuite{s}})
}
