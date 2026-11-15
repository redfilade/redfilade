package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type seenReq struct {
	method, name, version, auth string
}

// testServer answers server/discover, tools/list and tools/call. Paths:
// /json replies with a JSON body, /sse with an event stream, /redirect
// redirects to /json, /big sends an oversized body, /status/N fails with N.
func testServer(t *testing.T) (*httptest.Server, *[]seenReq, *sync.Mutex) {
	var mu sync.Mutex
	var seen []seenReq
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, seenReq{r.Header.Get("Mcp-Method"), r.Header.Get("Mcp-Name"), r.Header.Get("MCP-Protocol-Version"), r.Header.Get("Authorization")})
		mu.Unlock()
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/json", http.StatusFound)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/status/") {
			var code int
			fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/status/"), "%d", &code)
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(code)
			return
		}
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &m)
		if len(m.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		var result any = map[string]any{"resultType": "complete"}
		if m.Method == "tools/list" {
			result = map[string]any{"resultType": "complete", "tools": []any{map[string]any{"name": "echo", "inputSchema": map[string]any{"type": "object"}}}}
		}
		resp, _ := json.MarshalIndent(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result}, "", "  ")
		switch r.URL.Path {
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n")
			for _, line := range strings.Split(string(resp), "\n") {
				fmt.Fprintf(w, "data: %s\n", line)
			}
			fmt.Fprint(w, "\n")
		case "/big":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(m.ID) + `,"result":{"pad":"` + strings.Repeat("a", 3000) + `"}}`))
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Write(resp)
		}
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, &seen, &mu
}

func dial(t *testing.T, url string, o HTTPOptions, opts Options) (*Client, *HTTPTransport) {
	o.URL = url
	c, tr := DialHTTP(o, opts)
	t.Cleanup(tr.Close)
	return c, tr
}

func TestHTTPJSONAndSSE(t *testing.T) {
	srv, seen, mu := testServer(t)
	for _, path := range []string{"/json", "/sse"} {
		c, tr := dial(t, srv.URL+path, HTTPOptions{Token: "tok"}, Options{})
		ctx := context.Background()
		if _, err := c.Connect(ctx); err != nil {
			t.Fatalf("%s connect: %v", path, err)
		}
		tools, err := c.ListTools(ctx)
		if err != nil || len(tools) != 1 {
			t.Fatalf("%s tools: %v %v", path, tools, err)
		}
		if _, err := c.CallTool(ctx, "echo", map[string]any{}); err != nil {
			t.Fatalf("%s call: %v", path, err)
		}
		tr.Close()
		ex := c.Recorder().HTTP()
		if len(ex) != 3 || ex[2].Method != "tools/call" || ex[2].Name != "echo" || ex[2].Outcome != "result" || ex[2].Status != 200 {
			t.Fatalf("%s exchanges: %+v", path, ex)
		}
		for _, f := range c.Recorder().Frames() {
			if !json.Valid(f.Raw) {
				t.Errorf("%s frame %d is not one JSON message", path, f.Seq)
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, s := range *seen {
		if s.version != Protocol2026 || s.method == "" || s.auth != "Bearer tok" {
			t.Errorf("request headers %+v", s)
		}
		if s.method == "tools/call" && s.name != "echo" {
			t.Errorf("Mcp-Name missing: %+v", s)
		}
	}
}

func TestHTTPErrorsFailFast(t *testing.T) {
	srv, _, _ := testServer(t)
	for path, want := range map[string]string{"/status/401": "HTTP 401", "/status/429": "HTTP 429", "/redirect": "HTTP 302"} {
		c, tr := dial(t, srv.URL+path, HTTPOptions{}, Options{CallTimeout: 5 * time.Second})
		start := time.Now()
		_, err := c.Call(context.Background(), "tools/list", nil)
		var rpc *RPCError
		if !errors.As(err, &rpc) || !strings.Contains(rpc.Message, want) || time.Since(start) > 3*time.Second {
			t.Errorf("%s: %v", path, err)
		}
		tr.Close()
		ex := c.Recorder().HTTP()
		if len(ex) != 1 || ex[0].Outcome != "none" {
			t.Errorf("%s exchange: %+v", path, ex)
		}
		if path == "/status/429" && ex[0].RetryAfter != "7" {
			t.Errorf("Retry-After not recorded: %+v", ex[0])
		}
	}
}

func TestHTTPOversizedResponse(t *testing.T) {
	srv, _, _ := testServer(t)
	c, _ := dial(t, srv.URL+"/big", HTTPOptions{}, Options{MaxMessageBytes: 1024, CallTimeout: 3 * time.Second})
	if _, err := c.Call(context.Background(), "tools/list", nil); err == nil {
		t.Fatal("oversized response accepted")
	}
}

func TestHTTPCredentials(t *testing.T) {
	srv, seen, mu := testServer(t)
	c, tr := dial(t, srv.URL+"/json", HTTPOptions{Token: "good", ForeignToken: "other"}, Options{})
	labels := []string{AuthValid, AuthNone, AuthMalformed, AuthForgedNone, AuthForgedSig, AuthForeign}
	for _, l := range labels {
		tr.SetAuth(l)
		tr.SetTag("probe")
		if _, err := c.Call(context.Background(), "tools/list", nil); err != nil {
			t.Fatal(err)
		}
	}
	tr.Close()
	mu.Lock()
	defer mu.Unlock()
	got := map[string]string{}
	for i, s := range (*seen)[:len(labels)] {
		got[labels[i]] = s.auth
	}
	if got[AuthValid] != "Bearer good" || got[AuthNone] != "" || got[AuthForeign] != "Bearer other" || got[AuthMalformed] == "" {
		t.Fatalf("credentials: %v", got)
	}
	for _, l := range []string{AuthForgedNone, AuthForgedSig} {
		parts := strings.Split(strings.TrimPrefix(got[l], "Bearer "), ".")
		if len(parts) != 3 {
			t.Fatalf("%s: %q", l, got[l])
		}
		claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
		if !strings.Contains(string(claims), srv.URL) {
			t.Errorf("%s audience: %s", l, claims)
		}
		if (l == AuthForgedNone) != (parts[2] == "") {
			t.Errorf("%s signature part %q", l, parts[2])
		}
	}
	for _, e := range c.Recorder().HTTP() {
		if e.Tag != "probe" {
			t.Errorf("tag %+v", e)
		}
	}
}

func TestHTTPModifyNext(t *testing.T) {
	srv, seen, mu := testServer(t)
	c, tr := dial(t, srv.URL+"/json", HTTPOptions{}, Options{})
	tr.ModifyNext(func(r *http.Request) { r.Header.Set("Mcp-Name", "other_tool") })
	c.CallTool(context.Background(), "echo", nil)
	c.CallTool(context.Background(), "echo", nil)
	tr.Close()
	mu.Lock()
	defer mu.Unlock()
	if (*seen)[0].name != "other_tool" || (*seen)[1].name != "echo" {
		t.Fatalf("ModifyNext should apply once: %+v", *seen)
	}
}

func TestHTTPLegacySession(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Mcp-Session-Id"))
		var m struct {
			ID json.RawMessage `json:"id"`
		}
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &m)
		w.Header().Set("Mcp-Session-Id", "sess-1")
		if len(m.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, m.ID)
	}))
	defer srv.Close()
	c, tr := DialHTTP(HTTPOptions{URL: srv.URL}, Options{Protocol: Protocol2025})
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.Call(context.Background(), "tools/list", nil)
	tr.Close()
	if len(got) < 3 || got[0] != "" || got[len(got)-1] != "sess-1" {
		t.Fatalf("session ids sent: %q", got)
	}
}
