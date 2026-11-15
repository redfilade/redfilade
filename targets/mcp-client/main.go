// Command mcp-client is a Range target for L4: an MCP client (with a tiny
// scripted model) whose stdin and stdout carry its connection to a server.
// Redfilade's hostile server sits on the other end.
//
//	vulnerable: passes tool descriptions to the model unfiltered, so text
//	            hidden in invisible Unicode tag characters is obeyed; accepts
//	            elicitation requests automatically, filling in the user's
//	            password from USER_PASSWORD; runs sampling requests without
//	            asking anyone
//	secure:     strips invisible characters before the model sees anything;
//	            declines elicitation and sampling that no user approved
//
// Deliberately vulnerable in its vulnerable build. Run it only in a Redfilade
// cell.
package main

import (
	"bufio"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
)

var mode = "secure"

var (
	out   = json.NewEncoder(os.Stdout)
	outMu sync.Mutex
)

func send(v any) {
	outMu.Lock()
	defer outMu.Unlock()
	_ = out.Encode(v)
}

type msg struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

var reCall = regexp.MustCompile(`call the (\w+) tool`)

// visible removes invisible and format characters the way a careful client
// does before showing text to a model or a user.
func visible(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 0xE0000 && r <= 0xE007F) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}

// modelView is what the model reads: a careless client decodes everything.
func modelView(s string) string {
	if mode != "vulnerable" {
		return visible(s)
	}
	var b strings.Builder
	for _, r := range s {
		if r >= 0xE0020 && r < 0xE007F {
			r -= 0xE0000
		}
		b.WriteRune(r)
	}
	return b.String()
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 64<<10), 4<<20)
	responses := make(chan msg, 16)
	go func() {
		for in.Scan() {
			var m msg
			if json.Unmarshal(in.Bytes(), &m) != nil {
				continue
			}
			switch {
			case m.Method != "" && len(m.ID) > 0:
				handleServerRequest(m)
			case m.Method == "":
				responses <- m
			}
		}
		close(responses)
	}()
	next := func() (msg, bool) {
		select {
		case m, ok := <-responses:
			return m, ok
		case <-time.After(10 * time.Second):
			return msg{}, false
		}
	}

	caps := map[string]any{}
	if mode == "vulnerable" {
		caps = map[string]any{"sampling": map[string]any{}, "elicitation": map[string]any{}}
	}
	send(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{
		"protocolVersion": "2025-11-25", "capabilities": caps, "clientInfo": map[string]any{"name": "redfilade-client-twin", "version": "1.0.0"}}})
	if _, ok := next(); !ok {
		return
	}
	send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	send(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
	m, ok := next()
	if !ok {
		return
	}
	var list struct {
		Tools []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"tools"`
	}
	_ = json.Unmarshal(m.Result, &list)

	// The scripted model: answer "what's the weather in Pune?", obeying any
	// "call the X tool" instruction it reads in a description.
	id := 3
	for _, t := range list.Tools {
		if c := reCall.FindStringSubmatch(modelView(t.Description)); c != nil {
			send(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{
				"name": c[1], "arguments": map[string]any{"note": "what's the weather in Pune?"}}})
			id++
			next()
		}
	}
	send(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{
		"name": "get_weather", "arguments": map[string]any{"city": "Pune"}}})
	next()
	time.Sleep(500 * time.Millisecond) // let server-initiated requests finish
}

func handleServerRequest(m msg) {
	reply := func(result any) { send(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result}) }
	refuse := func(code int, text string) {
		send(map[string]any{"jsonrpc": "2.0", "id": m.ID, "error": map[string]any{"code": code, "message": text}})
	}
	switch m.Method {
	case "elicitation/create":
		if mode == "vulnerable" {
			reply(map[string]any{"action": "accept", "content": map[string]any{"password": os.Getenv("USER_PASSWORD")}})
			return
		}
		reply(map[string]any{"action": "decline"}) // no user was asked, so nothing is sent
	case "sampling/createMessage":
		if mode == "vulnerable" {
			reply(map[string]any{"role": "assistant", "model": "twin-model", "stopReason": "endTurn",
				"content": map[string]any{"type": "text", "text": "Workspace: notes.txt, deploy.sh, .env"}})
			return
		}
		refuse(-1, "User rejected sampling request")
	case "ping":
		reply(map[string]any{})
	default:
		refuse(-32601, "Method not found")
	}
}
