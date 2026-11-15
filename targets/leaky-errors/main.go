// Command leaky-errors is a Range target with two builds:
//
//	vulnerable: error replies leak a stack trace, source paths and the
//	            database connection string (with its password)
//	secure:     error replies are generic; details go to the server log only
//
// Build with -ldflags "-X main.mode=vulnerable" or "-X main.mode=secure".
// It speaks MCP over stdio, protocol 2026-07-28 (server/discover, _meta on
// every request) and the legacy 2025-11-25 handshake. It has no dependencies.
//
// This server is deliberately vulnerable in its vulnerable build. Run it only
// inside a Redfilade cell.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var mode = "secure"

const maxLine = 1 << 20

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Synthetic customers: invented data only.
var customers = map[string]string{
	"c-1001": "Asha Rao (synthetic)",
	"c-1002": "Ben Ortiz (synthetic)",
}

func worldDir() string {
	if d := os.Getenv("WORLD_DIR"); d != "" {
		return d
	}
	return "/world"
}

func dbURL() string {
	pw := "unset"
	b, err := os.ReadFile(filepath.Join(worldDir(), "config", "app.env"))
	if err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "DB_PASSWORD="); ok {
				pw = strings.TrimSpace(v)
			}
		}
	}
	return "postgres://app:" + pw + "@db.internal:5432/customers"
}

func main() {
	in := bufio.NewReaderSize(os.Stdin, 64<<10)
	out := json.NewEncoder(os.Stdout)
	for {
		line, err := in.ReadString('\n')
		if len(line) > maxLine {
			return
		}
		if strings.TrimSpace(line) != "" {
			handle(out, line)
		}
		if err != nil {
			return
		}
	}
}

func handle(out *json.Encoder, line string) {
	var req request
	if err := json.Unmarshal([]byte(line), &req); err != nil {
		return
	}
	if len(req.ID) == 0 {
		return // notification
	}
	reply := func(result any) {
		_ = out.Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}
	rpcErr := func(code int, msg string) {
		_ = out.Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": code, "message": msg}})
	}
	info := map[string]any{"name": "redfilade-target-leaky-errors", "version": "1.0.0"}
	switch req.Method {
	case "server/discover":
		reply(map[string]any{"resultType": "complete", "supportedVersions": []string{"2026-07-28", "2025-11-25"},
			"capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": info})
	case "initialize":
		reply(map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": info})
	case "tools/list":
		reply(map[string]any{"resultType": "complete", "ttlMs": 60000, "cacheScope": "shared", "tools": []any{
			map[string]any{
				"name":        "lookup_customer",
				"description": "Look up a customer's display name by id, for example c-1001.",
				"inputSchema": map[string]any{"type": "object", "required": []string{"id"},
					"properties": map[string]any{"id": map[string]any{"type": "string", "maxLength": 32}}},
			},
		}})
	case "tools/call":
		var p struct {
			Name      string                     `json:"name"`
			Arguments map[string]json.RawMessage `json:"arguments"`
		}
		_ = json.Unmarshal(req.Params, &p)
		if p.Name != "lookup_customer" {
			if mode == "vulnerable" {
				rpcErr(-32602, fmt.Sprintf("unknown tool %q\n%s", p.Name, fakeTrace("dispatch")))
			} else {
				rpcErr(-32602, "Unknown tool.")
			}
			return
		}
		var id string
		if err := json.Unmarshal(p.Arguments["id"], &id); err != nil || id == "" || len(id) > 32 || len(p.Arguments) != 1 {
			toolError(reply, fmt.Sprintf("decode arguments: %v", err))
			return
		}
		name, ok := customers[id]
		if !ok {
			toolError(reply, "customer "+id+" not found")
			return
		}
		reply(map[string]any{"resultType": "complete", "content": []any{map[string]any{"type": "text", "text": name}}})
	default:
		rpcErr(-32601, "Method not found.")
	}
}

// toolError is where the two builds differ.
func toolError(reply func(any), detail string) {
	if mode == "vulnerable" {
		// The classic mistake: hand the raw failure to the client.
		msg := "lookup failed: " + detail + "\nwhile querying " + dbURL() + "\n" + fakeTrace("lookup")
		reply(map[string]any{"resultType": "complete", "isError": true, "content": []any{map[string]any{"type": "text", "text": msg}}})
		return
	}
	// Secure: details stay in the server's own log; the client gets a
	// generic message.
	fmt.Fprintf(os.Stderr, "lookup_customer failed: %s\n", detail)
	reply(map[string]any{"resultType": "complete", "isError": true, "content": []any{map[string]any{"type": "text",
		"text": "Invalid request: provide one customer id, for example c-1001."}}})
}

func fakeTrace(fn string) string {
	return "goroutine 7 [running]:\nmain." + fn + "(...)\n\t/app/internal/store/customers.go:42 +0x1d\nmain.handle(...)\n\t/app/cmd/server/main.go:118 +0x2c4"
}
