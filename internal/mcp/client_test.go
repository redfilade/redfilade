package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// fakeServer reads requests from the client and answers with handle().
type fakeServer struct {
	in  *bufio.Reader
	out io.Writer
}

func pipePair(t *testing.T, opts Options) (*Client, *fakeServer, func()) {
	t.Helper()
	cr, sw := io.Pipe() // server -> client
	sr, cw := io.Pipe() // client -> server
	c := New(cr, cw, opts)
	return c, &fakeServer{in: bufio.NewReader(sr), out: sw}, func() { _ = sw.Close(); _ = cw.Close() }
}

func (s *fakeServer) next(t *testing.T) map[string]any {
	t.Helper()
	line, err := s.in.ReadBytes('\n')
	if err != nil {
		t.Errorf("server read: %v", err)
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		t.Errorf("bad frame %q: %v", line, err)
		return map[string]any{}
	}
	return m
}

func (s *fakeServer) send(t *testing.T, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if _, err := s.out.Write(append(b, '\n')); err != nil {
		t.Errorf("server write: %v", err)
	}
}

func TestDiscoverAndCallCarryMeta(t *testing.T) {
	c, s, stop := pipePair(t, Options{})
	defer stop()
	go func() {
		req := s.next(t)
		if req["method"] != "server/discover" {
			t.Errorf("first call = %v, want server/discover", req["method"])
		}
		meta := req["params"].(map[string]any)["_meta"].(map[string]any)
		if meta["io.modelcontextprotocol/protocolVersion"] != Protocol2026 {
			t.Errorf("missing protocolVersion in _meta: %v", meta)
		}
		if _, ok := meta["io.modelcontextprotocol/clientCapabilities"]; !ok {
			t.Errorf("missing clientCapabilities in _meta")
		}
		s.send(t, map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]any{"resultType": "complete", "supportedVersions": []string{Protocol2026}}})
		req = s.next(t)
		s.send(t, map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": "hi"}}}})
	}()
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, err := c.CallTool(context.Background(), "echo", map[string]any{"text": "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if res.ResultType != "complete" {
		t.Errorf("resultType = %q, want complete when omitted", res.ResultType)
	}
	if got := len(c.Recorder().Frames()); got != 4 {
		t.Errorf("recorded %d frames, want 4", got)
	}
}

func TestLegacyHandshake(t *testing.T) {
	c, s, stop := pipePair(t, Options{Protocol: Protocol2025})
	defer stop()
	go func() {
		req := s.next(t)
		if req["method"] != "initialize" {
			t.Errorf("method = %v, want initialize", req["method"])
		}
		if _, ok := req["params"].(map[string]any)["_meta"]; ok {
			t.Errorf("legacy requests must not carry 2026 _meta")
		}
		s.send(t, map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]any{}})
		if n := s.next(t); n["method"] != "notifications/initialized" {
			t.Errorf("want notifications/initialized, got %v", n["method"])
		}
	}()
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
}

func TestServerInitiatedRequestIsRefused(t *testing.T) {
	c, s, stop := pipePair(t, Options{})
	defer stop()
	go func() {
		req := s.next(t)
		// Before answering, the hostile server asks the client to sample.
		s.send(t, map[string]any{"jsonrpc": "2.0", "id": "srv-1", "method": "sampling/createMessage", "params": map[string]any{}})
		refusal := s.next(t)
		errObj, _ := refusal["error"].(map[string]any)
		if errObj == nil || errObj["code"].(float64) != codeMethodNotFound {
			t.Errorf("sampling request not refused: %v", refusal)
		}
		s.send(t, map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]any{"tools": []any{}}})
	}()
	if _, err := c.ListTools(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOversizedMessageIsRejected(t *testing.T) {
	c, s, stop := pipePair(t, Options{MaxMessageBytes: 1024})
	defer stop()
	go func() {
		_, _ = s.in.ReadBytes('\n')
		_, _ = s.out.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"` + strings.Repeat("A", 5000) + "\"}\n"))
	}()
	_, err := c.Call(context.Background(), "tools/list", nil)
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("err = %v, want ErrMessageTooLarge", err)
	}
}

func TestCallTimesOut(t *testing.T) {
	c, s, stop := pipePair(t, Options{CallTimeout: 100 * time.Millisecond})
	defer stop()
	go func() { _, _ = s.in.ReadBytes('\n') }() // read the request, never answer
	start := time.Now()
	_, err := c.Call(context.Background(), "tools/list", nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout not enforced")
	}
}

func TestTargetClosingIsReported(t *testing.T) {
	c, s, stop := pipePair(t, Options{})
	go func() { _, _ = s.in.ReadBytes('\n'); stop() }()
	_, err := c.Call(context.Background(), "tools/list", nil)
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v, want ErrClosed", err)
	}
}

func TestRPCErrorIsAnObservation(t *testing.T) {
	c, s, stop := pipePair(t, Options{})
	defer stop()
	go func() {
		req := s.next(t)
		s.send(t, map[string]any{"jsonrpc": "2.0", "id": req["id"], "error": map[string]any{"code": -32602, "message": "bad args"}})
	}()
	res, err := c.CallTool(context.Background(), "x", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.RPCError == nil || res.RPCError.Code != -32602 {
		t.Fatalf("want RPC error recorded, got %+v", res)
	}
}

func TestMalformedFramesAreKeptAsStrings(t *testing.T) {
	r := NewRecorder(64)
	r.add(DirServerToClient, []byte("not json {"))
	f := r.Frames()[0]
	var s string
	if err := json.Unmarshal(f.Raw, &s); err != nil || s != "not json {" {
		t.Fatalf("malformed frame not stored as string: %s", f.Raw)
	}
}
