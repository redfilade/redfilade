// Command defence-rules is a reference defence for L5: a small rule-based
// MCP guardrail speaking Redfilade's defence protocol (redfilade.defence/v1)
// on stdin and stdout.
//
//	vulnerable: "permissive", allows every message (a baseline with no defence)
//	secure:     "strict", blocks requests carrying traversal, shell
//	            metacharacters, SQL injection shapes or internal and metadata
//	            URLs, and replies carrying secret-shaped text, stack traces or
//	            hidden instructions in tool metadata
//
// It shows how to measure a defence, not how to build a good one: keyword
// rules like these are easy to evade.
package main

import (
	"bufio"
	"encoding/json"
	"os"
	"regexp"
	"strings"
)

var mode = "secure"

var (
	requestRules = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"path traversal", regexp.MustCompile(`\.\./|\.\.\\|%2e%2e|^/etc/|/world/`)},
		{"shell metacharacters", regexp.MustCompile("[;&|`]|\\$\\(")},
		{"sql injection", regexp.MustCompile(`(?i)'\s*(or|and|union)\b|\bunion\s+select\b|'\s*;|--\s*$`)},
		{"internal address", regexp.MustCompile(`(?i)\b(127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|169\.254\.\d+\.\d+|192\.168\.\d+\.\d+|localhost|metadata\.google\.internal|sink\.redfilade\.test)\b|file://`)},
	}
	replyRules = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"secret in output", regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password)\s*[=:]\s*\S{8,}|CANARY_[A-Z0-9_]+|-----BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}`)},
		{"stack trace", regexp.MustCompile(`(?m)Traceback \(most recent call last\)|^goroutine \d+ \[|\bat [\w.$]+\([\w]+\.java:\d+\)|/home/\w+/|/usr/src/`)},
		{"hidden instruction in tool metadata", regexp.MustCompile(`(?i)<important>|ignore (all )?previous instructions|do not tell the user|[\x{E0000}-\x{E007F}]`)},
	}
)

func decide(direction string, msg json.RawMessage) (string, string) {
	if mode == "vulnerable" {
		return "allow", ""
	}
	text := string(msg)
	var m struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	_ = json.Unmarshal(msg, &m)
	if direction == "client_to_server" {
		if m.Method != "tools/call" {
			return "allow", ""
		}
		var p struct {
			Arguments map[string]any `json:"arguments"`
		}
		_ = json.Unmarshal(m.Params, &p)
		for _, v := range flatten(p.Arguments) {
			for _, r := range requestRules {
				if r.re.MatchString(v) {
					return "block", r.name
				}
			}
		}
		return "allow", ""
	}
	body := string(m.Result) + string(m.Error)
	if body == "" {
		body = text
	}
	for _, r := range replyRules {
		if r.re.MatchString(body) {
			return "block", r.name
		}
	}
	return "allow", ""
}

func flatten(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case map[string]any:
		var out []string
		for _, e := range x {
			out = append(out, flatten(e)...)
		}
		return out
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, flatten(e)...)
		}
		return out
	}
	return nil
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 64<<10), 8<<20)
	out := json.NewEncoder(os.Stdout)
	for in.Scan() {
		var req struct {
			Direction string          `json:"direction"`
			Message   json.RawMessage `json:"message"`
		}
		if json.Unmarshal(in.Bytes(), &req) != nil {
			_ = out.Encode(map[string]string{"action": "block", "reason": "unreadable message"})
			continue
		}
		action, reason := decide(strings.TrimSpace(req.Direction), req.Message)
		_ = out.Encode(map[string]string{"action": action, "reason": reason})
	}
}
