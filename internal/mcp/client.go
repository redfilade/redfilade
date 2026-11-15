// Package mcp is a minimal, dependency-free MCP client for driving targets
// under test over stdio.
//
// The server on the other end is hostile by assumption: every message is
// size-limited, every call has a deadline, server-initiated requests are
// refused, and every frame in both directions is recorded as evidence.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Protocol revisions this client speaks (ADR-0012).
const (
	Protocol2026 = "2026-07-28"
	Protocol2025 = "2025-11-25"
)

// Default limits. A target can never make the client buffer more than
// MaxMessageBytes for a single frame.
const (
	DefaultMaxMessageBytes = 4 << 20
	DefaultCallTimeout     = 15 * time.Second
)

// JSON-RPC error codes used by the client.
const (
	codeMethodNotFound = -32601
)

// ErrMessageTooLarge is returned when a target sends a frame over the limit.
var ErrMessageTooLarge = errors.New("mcp: message exceeds size limit")

// ErrClosed is returned when the target closed its output.
var ErrClosed = errors.New("mcp: target closed the connection")

// RPCError is a JSON-RPC error object returned by the target.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string { return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message) }

// Options configure a Client.
type Options struct {
	Protocol        string // Protocol2026 (default) or Protocol2025
	ClientName      string
	ClientVersion   string
	MaxMessageBytes int
	CallTimeout     time.Duration
	Recorder        *Recorder
}

// Client talks to one target over a pair of streams.
type Client struct {
	opts   Options
	w      io.Writer
	wmu    sync.Mutex
	nextID atomic.Int64
	rec    *Recorder

	pendingMu sync.Mutex
	pending   map[string]chan *message

	readErrMu sync.Mutex
	readErr   error
	done      chan struct{}
}

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// New starts reading from r and returns a client that writes to w.
func New(r io.Reader, w io.Writer, opts Options) *Client {
	if opts.Protocol == "" {
		opts.Protocol = Protocol2026
	}
	if opts.ClientName == "" {
		opts.ClientName = "redfilade"
	}
	if opts.ClientVersion == "" {
		opts.ClientVersion = "0.0.0-dev"
	}
	if opts.MaxMessageBytes <= 0 {
		opts.MaxMessageBytes = DefaultMaxMessageBytes
	}
	if opts.CallTimeout <= 0 {
		opts.CallTimeout = DefaultCallTimeout
	}
	if opts.Recorder == nil {
		opts.Recorder = NewRecorder(opts.MaxMessageBytes)
	}
	c := &Client{opts: opts, w: w, rec: opts.Recorder, pending: map[string]chan *message{}, done: make(chan struct{})}
	go c.readLoop(r)
	return c
}

// Recorder returns the wire recorder holding every frame of this connection.
func (c *Client) Recorder() *Recorder { return c.rec }

// Protocol returns the protocol revision in use.
func (c *Client) Protocol() string { return c.opts.Protocol }

func (c *Client) readLoop(r io.Reader) {
	defer close(c.done)
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := readLine(br, c.opts.MaxMessageBytes)
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = ErrClosed
			}
			c.setReadErr(err)
			return
		}
		if len(line) == 0 {
			continue
		}
		c.rec.add(DirServerToClient, line)
		var m message
		if json.Unmarshal(line, &m) != nil {
			continue // malformed frames are kept as evidence, not trusted
		}
		switch {
		case m.Method != "" && len(m.ID) > 0:
			// A server-initiated request (sampling, elicitation, ...). The
			// range client never grants these.
			c.reply(m.ID, nil, &RPCError{Code: codeMethodNotFound, Message: "not supported by the range client"})
		case m.Method != "":
			// Notification: recorded above, otherwise ignored.
		default:
			c.pendingMu.Lock()
			ch := c.pending[string(m.ID)]
			delete(c.pending, string(m.ID))
			c.pendingMu.Unlock()
			if ch != nil {
				ch <- &m
			}
		}
	}
}

// readLine reads one newline-delimited frame, refusing frames over limit.
func readLine(br *bufio.Reader, limit int) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(buf)+len(chunk) > limit+1 {
			return nil, ErrMessageTooLarge
		}
		buf = append(buf, chunk...)
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if len(buf) > 0 && errors.Is(err, io.EOF) {
			break
		}
		return nil, err
	}
	for len(buf) > 0 && (buf[len(buf)-1] == '\n' || buf[len(buf)-1] == '\r') {
		buf = buf[:len(buf)-1]
	}
	return buf, nil
}

func (c *Client) setReadErr(err error) {
	c.readErrMu.Lock()
	defer c.readErrMu.Unlock()
	if c.readErr == nil {
		c.readErr = err
	}
}

func (c *Client) readError() error {
	c.readErrMu.Lock()
	defer c.readErrMu.Unlock()
	if c.readErr == nil {
		return ErrClosed
	}
	return c.readErr
}

func (c *Client) write(m any) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.rec.add(DirClientToServer, b)
	_, err = c.w.Write(append(b, '\n'))
	return err
}

func (c *Client) reply(id json.RawMessage, result any, rpcErr *RPCError) {
	resp := map[string]any{"jsonrpc": "2.0", "id": id}
	if rpcErr != nil {
		resp["error"] = rpcErr
	} else {
		resp["result"] = result
	}
	_ = c.write(resp)
}

// meta is the per-request _meta block required by protocol 2026-07-28.
func (c *Client) meta() map[string]any {
	return map[string]any{
		"io.modelcontextprotocol/protocolVersion":    c.opts.Protocol,
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		"io.modelcontextprotocol/clientInfo":         map[string]any{"name": c.opts.ClientName, "version": c.opts.ClientVersion},
	}
}

// Call sends a request and waits for its response or the deadline.
func (c *Client) Call(ctx context.Context, method string, params map[string]any) (json.RawMessage, error) {
	if params == nil {
		params = map[string]any{}
	}
	if c.opts.Protocol == Protocol2026 {
		params["_meta"] = c.meta()
	}
	n := c.nextID.Add(1)
	id := strconv.FormatInt(n, 10)
	ch := make(chan *message, 1)
	c.pendingMu.Lock()
	c.pending[id] = ch
	c.pendingMu.Unlock()
	defer func() {
		c.pendingMu.Lock()
		delete(c.pending, id)
		c.pendingMu.Unlock()
	}()

	if err := c.write(map[string]any{"jsonrpc": "2.0", "id": n, "method": method, "params": params}); err != nil {
		return nil, fmt.Errorf("mcp: write %s: %w", method, err)
	}
	ctx, cancel := context.WithTimeout(ctx, c.opts.CallTimeout)
	defer cancel()
	select {
	case m := <-ch:
		if m.Error != nil {
			return nil, m.Error
		}
		return m.Result, nil
	case <-c.done:
		return nil, c.readError()
	case <-ctx.Done():
		return nil, fmt.Errorf("mcp: %s: %w", method, ctx.Err())
	}
}

// Notify sends a notification (no response expected).
func (c *Client) Notify(method string, params map[string]any) error {
	if params == nil {
		params = map[string]any{}
	}
	return c.write(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
}

// Connect performs the protocol's opening step: server/discover for
// 2026-07-28, or the initialize handshake for 2025-11-25. It returns the raw
// discovery or initialize result.
func (c *Client) Connect(ctx context.Context) (json.RawMessage, error) {
	if c.opts.Protocol == Protocol2026 {
		return c.Call(ctx, "server/discover", nil)
	}
	res, err := c.Call(ctx, "initialize", map[string]any{
		"protocolVersion": c.opts.Protocol,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": c.opts.ClientName, "version": c.opts.ClientVersion},
	})
	if err != nil {
		return nil, err
	}
	return res, c.Notify("notifications/initialized", nil)
}

// Tool is a tool advertised by the target.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// ListTools returns the target's tools.
func (c *Client) ListTools(ctx context.Context) ([]Tool, error) {
	raw, err := c.Call(ctx, "tools/list", nil)
	if err != nil {
		return nil, err
	}
	var res struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("mcp: tools/list result: %w", err)
	}
	return res.Tools, nil
}

// CallResult is the outcome of tools/call.
type CallResult struct {
	ResultType string          // "complete" when an older server omits it
	IsError    bool            // the tool reported an error
	RPCError   *RPCError       // the call failed at the JSON-RPC level
	Raw        json.RawMessage // the full result, kept for the oracle
}

// CallTool invokes a tool. A JSON-RPC error is returned inside CallResult,
// because for the range an error response is an observation, not a failure.
func (c *Client) CallTool(ctx context.Context, name string, args map[string]any) (*CallResult, error) {
	if args == nil {
		args = map[string]any{}
	}
	raw, err := c.Call(ctx, "tools/call", map[string]any{"name": name, "arguments": args})
	var rpcErr *RPCError
	if errors.As(err, &rpcErr) {
		return &CallResult{ResultType: "error", RPCError: rpcErr}, nil
	}
	if err != nil {
		return nil, err
	}
	var res struct {
		ResultType string `json:"resultType"`
		IsError    bool   `json:"isError"`
	}
	_ = json.Unmarshal(raw, &res)
	if res.ResultType == "" {
		res.ResultType = "complete"
	}
	return &CallResult{ResultType: res.ResultType, IsError: res.IsError, Raw: raw}, nil
}
