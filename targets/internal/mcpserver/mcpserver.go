// Package mcpserver is a tiny, dependency-free MCP stdio server used by Range
// targets. It speaks 2026-07-28 (server/discover) and the 2025-11-25
// initialize handshake. Targets register tools; the package handles framing.
package mcpserver

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
)

// Tool is one tool a target exposes.
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
	// Handle returns (text, isError). Args are the decoded JSON arguments.
	Handle func(args map[string]any) (string, bool)
}

// Serve runs the stdio loop until stdin closes.
func Serve(name string, tools []Tool) {
	byName := map[string]Tool{}
	for _, t := range tools {
		byName[t.Name] = t
	}
	in := bufio.NewReaderSize(os.Stdin, 64<<10)
	out := json.NewEncoder(os.Stdout)
	for {
		line, err := in.ReadString('\n')
		if len(line) > 1<<20 {
			return
		}
		if strings.TrimSpace(line) != "" {
			handle(out, line, name, tools, byName)
		}
		if err != nil {
			return
		}
	}
}

func handle(out *json.Encoder, line, name string, tools []Tool, byName map[string]Tool) {
	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if json.Unmarshal([]byte(line), &req) != nil || len(req.ID) == 0 {
		return
	}
	reply := func(result any) { _ = out.Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result}) }
	fail := func(code int, msg string) {
		_ = out.Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": code, "message": msg}})
	}
	info := map[string]any{"name": name, "version": "1.0.0"}
	switch req.Method {
	case "server/discover":
		reply(map[string]any{"resultType": "complete", "supportedVersions": []string{"2026-07-28", "2025-11-25"},
			"capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": info})
	case "initialize":
		reply(map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": info})
	case "tools/list":
		var list []any
		for _, t := range tools {
			list = append(list, map[string]any{"name": t.Name, "description": t.Description, "inputSchema": t.InputSchema})
		}
		reply(map[string]any{"resultType": "complete", "tools": list})
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		_ = json.Unmarshal(req.Params, &p)
		t, ok := byName[p.Name]
		if !ok {
			fail(-32602, "Unknown tool.")
			return
		}
		text, isErr := t.Handle(p.Arguments)
		reply(map[string]any{"resultType": "complete", "isError": isErr, "content": []any{map[string]any{"type": "text", "text": text}}})
	default:
		fail(-32601, "Method not found.")
	}
}

// Str returns args[key] if it is a string.
func Str(args map[string]any, key string) (string, bool) {
	v, ok := args[key].(string)
	return v, ok
}

// WorldDir is where the run's world is mounted.
func WorldDir() string {
	if d := os.Getenv("WORLD_DIR"); d != "" {
		return d
	}
	return "/world"
}
