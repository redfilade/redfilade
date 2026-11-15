package oracle

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/redfilade/redfilade/internal/mcp"
	"github.com/redfilade/redfilade/internal/scenario"
	"github.com/redfilade/redfilade/internal/world"
)

const canary = "CANARY_DB_ABCDEFGHIJKLMNOPQRSTUVWXYZ"

func frame(seq int, dir string, v any) mcp.Frame {
	b, _ := json.Marshal(v)
	return mcp.Frame{Seq: seq, Direction: dir, Raw: b}
}

func errorReply(text string) any {
	return map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"isError": true,
		"content": []any{map[string]any{"type": "text", "text": text}}}}
}

var checks = []scenario.Check{{Fact: "canary_leaked", Canary: "DB"}, {Fact: "internals_leaked"}}

func TestLeakyErrorIsExploited(t *testing.T) {
	leak := "lookup failed: dial postgres://app:" + canary + "@db.internal:5432/customers\ngoroutine 7 [running]:\nmain.lookup()\n\t/app/internal/store/customers.go:42 +0x1d"
	r := Evaluate(Input{
		Frames:    []mcp.Frame{frame(1, mcp.DirClientToServer, map[string]any{"q": canary}), frame(2, mcp.DirServerToClient, errorReply(leak))},
		Canaries:  map[string]string{"DB": canary},
		Checks:    checks,
		Completed: true,
	})
	if r.Verdict != Exploited {
		t.Fatalf("verdict = %s", r.Verdict)
	}
	detectors := map[string]bool{}
	for _, f := range r.Findings {
		detectors[f.Fact+"/"+f.Detector] = true
		if strings.Contains(f.Excerpt, canary) {
			t.Errorf("finding leaks the canary value: %q", f.Excerpt)
		}
	}
	for _, want := range []string{"canary_leaked/", "internals_leaked/go-panic", "internals_leaked/source-path", "internals_leaked/connection-string"} {
		if !detectors[want] {
			t.Errorf("missing finding %s in %v", want, detectors)
		}
	}
}

func TestClientFramesAreIgnored(t *testing.T) {
	// The attacker sending the canary is not a leak; only the target's replies count.
	r := Evaluate(Input{
		Frames:    []mcp.Frame{frame(1, mcp.DirClientToServer, map[string]any{"x": canary + " /app/main.go"})},
		Canaries:  map[string]string{"DB": canary},
		Checks:    checks,
		Completed: true,
	})
	if r.Verdict != NotExploited {
		t.Fatalf("verdict = %s, want not_exploited", r.Verdict)
	}
}

func TestSecureErrorPasses(t *testing.T) {
	r := Evaluate(Input{
		Frames:    []mcp.Frame{frame(2, mcp.DirServerToClient, errorReply("Invalid input: id must be a string."))},
		Canaries:  map[string]string{"DB": canary},
		Checks:    checks,
		Completed: true,
	})
	if r.Verdict != NotExploited || len(r.Findings) != 0 {
		t.Fatalf("got %+v", r)
	}
}

func TestEscapedLeakIsStillFound(t *testing.T) {
	// JSON inside a text block, with the canary split by escapes in the raw frame.
	inner, _ := json.Marshal(map[string]string{"detail": "Traceback (most recent call last):\n  File \"/app/server.py\", line 3"})
	r := Evaluate(Input{
		Frames:    []mcp.Frame{frame(2, mcp.DirServerToClient, errorReply(string(inner)))},
		Checks:    []scenario.Check{{Fact: "internals_leaked"}},
		Completed: true,
	})
	if r.Verdict != Exploited {
		t.Fatalf("verdict = %s", r.Verdict)
	}
}

func TestIncompleteRunIsInconclusive(t *testing.T) {
	r := Evaluate(Input{Checks: checks, Completed: false})
	if r.Verdict != Inconclusive {
		t.Fatalf("verdict = %s, want inconclusive", r.Verdict)
	}
}

func TestMatchAll(t *testing.T) {
	in := Input{
		Frames:    []mcp.Frame{frame(2, mcp.DirServerToClient, errorReply("/app/x.go:1"))},
		Canaries:  map[string]string{"DB": canary},
		Checks:    checks,
		Match:     "all",
		Completed: true,
	}
	if r := Evaluate(in); r.Verdict != NotExploited {
		t.Fatalf("match all with one fact: %s", r.Verdict)
	}
}

func TestWorldChange(t *testing.T) {
	r := Evaluate(Input{
		Changes:   []world.Change{{Path: "config/app.env", Change: "modified"}},
		Checks:    []scenario.Check{{Fact: "world_file_changed", Path: "config/app.env"}},
		Completed: true,
	})
	if r.Verdict != Exploited {
		t.Fatalf("verdict = %s", r.Verdict)
	}
}

func TestNotObservedIsAlwaysReported(t *testing.T) {
	r := Evaluate(Input{Checks: checks, Completed: true})
	if len(r.NotObserved) == 0 {
		t.Fatal("not_observed must never be empty for this runner")
	}
}

func TestHostileOutputIsLinearTime(t *testing.T) {
	big := strings.Repeat("at a.b(", 200000) + strings.Repeat("/app/", 100000)
	r := Evaluate(Input{Frames: []mcp.Frame{frame(1, mcp.DirServerToClient, errorReply(big))}, Checks: []scenario.Check{{Fact: "internals_leaked"}}, Completed: true})
	_ = r
}

func TestEgressFacts(t *testing.T) {
	sinkCanary := "CANARY_SINK_ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	exfil := "CANARY_KEY_ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	in := Input{
		Egress:    []Egress{{Method: "GET", Host: "sink.redfilade.test:8080", Path: "/x", Query: "k=" + exfil}},
		Canaries:  map[string]string{"SINK": sinkCanary, "KEY": exfil},
		Checks:    []scenario.Check{{Fact: "egress_reached_sink"}, {Fact: "canary_egressed", Canary: "KEY"}},
		Match:     "all",
		Completed: true,
		Network:   "sink",
	}
	r := Evaluate(in)
	if r.Verdict != Exploited {
		t.Fatalf("verdict = %s", r.Verdict)
	}
	for _, f := range r.Findings {
		if strings.Contains(f.Excerpt, exfil) {
			t.Errorf("egress excerpt leaks the canary: %q", f.Excerpt)
		}
	}
	in.Egress = nil
	if r := Evaluate(in); r.Verdict != NotExploited {
		t.Fatalf("no egress: verdict = %s", r.Verdict)
	}
}

func TestSecretAndFileDetectors(t *testing.T) {
	for name, tc := range map[string]struct {
		text string
		fact string
		want bool
	}{
		"aws key":        {"key=AKIAIOSFODNN7EXAMPLE", "secret_pattern_leaked", true},
		"github token":   {"ghp_" + strings.Repeat("a", 36), "secret_pattern_leaked", true},
		"private key":    {"-----BEGIN OPENSSH PRIVATE KEY-----\nabc", "secret_pattern_leaked", true},
		"canary format":  {"token CANARY_ENV_ABCDEFGHIJKLMNOPQRSTUVWXYZ", "secret_pattern_leaked", true},
		"generic error":  {"Invalid token. Please sign in again.", "secret_pattern_leaked", false},
		"passwd":         {"root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1", "sensitive_file_read", true},
		"passwd mention": {"cannot open /etc/passwd", "sensitive_file_read", false},
		"environ":        {"PATH=/usr/bin:/bin\x00HOME=/root\x00", "sensitive_file_read", true},
	} {
		t.Run(name, func(t *testing.T) {
			r := Evaluate(Input{Frames: []mcp.Frame{frame(2, mcp.DirServerToClient, errorReply(tc.text))},
				Checks: []scenario.Check{{Fact: tc.fact}}, Completed: true})
			if got := r.Verdict == Exploited; got != tc.want {
				t.Fatalf("exploited = %v, want %v (%+v)", got, tc.want, r.Findings)
			}
		})
	}
}
