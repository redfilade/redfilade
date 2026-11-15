// Package defence puts a gateway or guardrail between Redfilade's client and
// a target, for L5 measurement (ADR-0024).
//
// A defence speaks a line protocol on its stdin and stdout
// (redfilade.defence/v1). For every MCP message Redfilade writes
//
//	{"direction":"client_to_server"|"server_to_client","message":{...}}
//
// and the defence answers with one line, {"action":"allow"} or
// {"action":"block","reason":"..."}. Any product can be measured through a
// small adapter. A defence that crashes, stalls or answers anything else
// blocks the message ("fail closed"), and the failure is recorded.
package defence

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
)

// Directions.
const (
	ClientToServer = "client_to_server"
	ServerToClient = "server_to_client"
)

// DecisionTimeout bounds how long a defence may take for one message.
const DecisionTimeout = 5 * time.Second

// Filter decides whether a message may pass.
type Filter interface {
	Decide(direction string, msg []byte) (allow bool, reason string)
}

// Proc is a defence process reached over a pair of streams.
type Proc struct {
	mu     sync.Mutex
	in     io.Writer
	lines  chan []byte
	broken string
}

// NewProc talks to a defence whose stdin is in and stdout is out.
func NewProc(in io.Writer, out io.Reader) *Proc {
	p := &Proc{in: in, lines: make(chan []byte, 1)}
	go func() {
		br := bufio.NewReaderSize(out, 64<<10)
		for {
			line, err := br.ReadBytes('\n')
			if len(line) > 0 {
				p.lines <- line
			}
			if err != nil {
				close(p.lines)
				return
			}
		}
	}()
	return p
}

// Decide asks the defence about one message, failing closed.
func (p *Proc) Decide(direction string, msg []byte) (bool, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.broken != "" {
		return false, "defence unavailable: " + p.broken
	}
	req, _ := json.Marshal(map[string]any{"direction": direction, "message": json.RawMessage(msg)})
	if !json.Valid(msg) {
		req, _ = json.Marshal(map[string]any{"direction": direction, "message": string(msg)})
	}
	if _, err := p.in.Write(append(req, '\n')); err != nil {
		p.broken = "write failed"
		return false, "defence unavailable: " + p.broken
	}
	select {
	case line, ok := <-p.lines:
		if !ok {
			p.broken = "it exited"
			return false, "defence unavailable: " + p.broken
		}
		var d struct {
			Action string `json:"action"`
			Reason string `json:"reason"`
		}
		if json.Unmarshal(line, &d) != nil || (d.Action != "allow" && d.Action != "block") {
			return false, "defence gave an invalid answer"
		}
		if len(d.Reason) > 200 {
			d.Reason = d.Reason[:200]
		}
		return d.Action == "allow", d.Reason
	case <-time.After(DecisionTimeout):
		p.broken = "it did not answer within " + DecisionTimeout.String()
		return false, "defence unavailable: " + p.broken
	}
}

// Block is one message the defence stopped.
type Block struct {
	Direction string `json:"direction"`
	Method    string `json:"method,omitempty"`
	Tool      string `json:"tool,omitempty"`
	Reason    string `json:"reason"`
}

// Stats counts a run's decisions.
type Stats struct {
	mu        sync.Mutex
	decisions int
	blocked   []Block
}

// Summary is a copy of Stats for reports.
type Summary struct {
	Image     string  `json:"image,omitempty"`
	Decisions int     `json:"decisions"`
	Blocked   []Block `json:"blocked"`
}

func (s *Stats) note(dir string, msg []byte, allow bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decisions++
	if allow {
		return
	}
	var m struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	_ = json.Unmarshal(msg, &m)
	s.blocked = append(s.blocked, Block{Direction: dir, Method: m.Method, Tool: m.Params.Name, Reason: reason})
}

// Snapshot returns a copy of the counts.
func (s *Stats) Snapshot() Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Summary{Decisions: s.decisions, Blocked: append([]Block{}, s.blocked...)}
}

// BlockedCalls counts blocked client tool calls and replies to them.
func (s *Stats) BlockedCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.blocked)
}

// Wrap returns streams for a client that pass every message through f on its
// way to and from the target. A blocked request is answered with a JSON-RPC
// error so the client never hangs; a blocked reply is replaced by one.
func Wrap(f Filter, fromTarget io.Reader, toTarget io.Writer) (io.Reader, io.Writer, *Stats) {
	st := &Stats{}
	pr, pw := io.Pipe()
	// Messages for the client go through a queue drained by one goroutine,
	// so neither direction ever waits for the client to read.
	q := &queue{cond: sync.NewCond(&sync.Mutex{})}
	go func() {
		for {
			b, ok := q.pop()
			if !ok {
				_ = pw.Close()
				return
			}
			if _, err := pw.Write(append(b, '\n')); err != nil {
				return
			}
		}
	}()
	deliver := q.push
	blockedReply := func(msg []byte, reason string) []byte {
		var m struct {
			ID json.RawMessage `json:"id"`
		}
		if json.Unmarshal(msg, &m) != nil || len(m.ID) == 0 || string(m.ID) == "null" {
			return nil
		}
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "error": map[string]any{
			"code": -32001, "message": "blocked by defence: " + reason}})
		return b
	}
	go func() {
		br := bufio.NewReaderSize(fromTarget, 64<<10)
		for {
			line, err := br.ReadBytes('\n')
			if b := bytes.TrimRight(line, "\r\n"); len(b) > 0 {
				allow, reason := f.Decide(ServerToClient, b)
				st.note(ServerToClient, b, allow, reason)
				if allow {
					deliver(b)
				} else if r := blockedReply(b, reason); r != nil {
					deliver(r)
				}
			}
			if err != nil {
				q.close()
				return
			}
		}
	}()
	w := writerFunc(func(p []byte) (int, error) {
		for _, line := range bytes.Split(bytes.TrimRight(p, "\r\n"), []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			allow, reason := f.Decide(ClientToServer, line)
			st.note(ClientToServer, line, allow, reason)
			if allow {
				if _, err := toTarget.Write(append(append([]byte{}, line...), '\n')); err != nil {
					return 0, err
				}
				continue
			}
			var m struct {
				Method string `json:"method"`
			}
			_ = json.Unmarshal(line, &m)
			if m.Method != "" {
				if r := blockedReply(line, reason); r != nil {
					deliver(r)
				}
			}
		}
		return len(p), nil
	})
	return pr, w, st
}

// queue is an unbounded FIFO of messages for the client.
type queue struct {
	cond   *sync.Cond
	items  [][]byte
	closed bool
}

func (q *queue) push(b []byte) {
	q.cond.L.Lock()
	defer q.cond.L.Unlock()
	if !q.closed {
		q.items = append(q.items, append([]byte{}, b...))
		q.cond.Signal()
	}
}

func (q *queue) close() {
	q.cond.L.Lock()
	defer q.cond.L.Unlock()
	q.closed = true
	q.cond.Broadcast()
}

// pop returns the next message, or false once the queue is closed and empty.
func (q *queue) pop() ([]byte, bool) {
	q.cond.L.Lock()
	defer q.cond.L.Unlock()
	for len(q.items) == 0 && !q.closed {
		q.cond.Wait()
	}
	if len(q.items) == 0 {
		return nil, false
	}
	b := q.items[0]
	q.items = q.items[1:]
	return b, true
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// --- benign task set -----------------------------------------------------------

//go:embed benign.json
var benignJSON []byte

// BenignCall is one legitimate tool call.
type BenignCall struct {
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
}

// BenignTask is a set of legitimate calls against a scenario's secure twin.
type BenignTask struct {
	Scenario string       `json:"scenario"`
	Calls    []BenignCall `json:"calls"`
}

// Benign returns the built-in benign task set.
func Benign() ([]BenignTask, error) {
	var out []BenignTask
	if err := json.Unmarshal(benignJSON, &out); err != nil {
		return nil, err
	}
	for _, t := range out {
		if t.Scenario == "" || len(t.Calls) == 0 {
			return nil, errors.New("benign.json: every task needs a scenario and calls")
		}
		for _, c := range t.Calls {
			if strings.TrimSpace(c.Tool) == "" {
				return nil, errors.New("benign.json: every call needs a tool")
			}
		}
	}
	return out, nil
}
