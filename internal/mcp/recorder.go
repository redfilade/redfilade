package mcp

import (
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// Direction of a recorded frame.
const (
	DirClientToServer = "client_to_server"
	DirServerToClient = "server_to_client"
)

// Frame is one recorded JSON-RPC message.
type Frame struct {
	Seq       int    `json:"seq"`
	Direction string `json:"direction"`
	OffsetMS  int64  `json:"offset_ms"`
	// Raw holds the frame exactly as sent. Frames that are not valid JSON are
	// stored as a JSON string so the evidence stays parseable.
	Raw json.RawMessage `json:"raw"`
}

// Recorder keeps every frame of a connection, in order, for the oracle.
type Recorder struct {
	mu     sync.Mutex
	start  time.Time
	frames []Frame
	http   []HTTPExchange
	limit  int
}

// HTTPExchange is one HTTP request and its response, recorded for the oracle
// alongside the JSON-RPC frames when the target is reached over HTTP.
type HTTPExchange struct {
	Seq             int    `json:"seq"`            // the request frame
	Method          string `json:"method"`         // JSON-RPC method
	Name            string `json:"name,omitempty"` // tool, resource or prompt name
	Auth            string `json:"auth"`           // which credential was sent: valid, none, malformed, forged-none, forged-signature, foreign
	Tag             string `json:"tag,omitempty"`  // attack tag, e.g. burst or mismatch
	Status          int    `json:"status"`         // 0 when no response arrived
	Outcome         string `json:"outcome"`        // result, error, none or transport-error
	RetryAfter      string `json:"retry_after,omitempty"`
	WWWAuthenticate string `json:"www_authenticate,omitempty"`
	OffsetMS        int64  `json:"offset_ms"`
	DurationMS      int64  `json:"duration_ms"`
}

// NewRecorder creates a recorder; frames longer than limit are truncated.
func NewRecorder(limit int) *Recorder {
	return &Recorder{start: time.Now(), limit: limit}
}

func (r *Recorder) add(dir string, b []byte) {
	cp := make([]byte, len(b))
	copy(cp, b)
	if len(cp) > r.limit {
		cp = cp[:r.limit]
	}
	raw := json.RawMessage(cp)
	if !json.Valid(cp) {
		s, _ := json.Marshal(string(cp))
		raw = s
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frames = append(r.frames, Frame{Seq: len(r.frames) + 1, Direction: dir, OffsetMS: time.Since(r.start).Milliseconds(), Raw: raw})
}

func (r *Recorder) addHTTP(e HTTPExchange) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.http = append(r.http, e)
}

// lastSeq is the sequence number of the most recent frame.
func (r *Recorder) lastSeq() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.frames)
}

func (r *Recorder) since() time.Duration { return time.Since(r.start) }

// HTTP returns a copy of all recorded HTTP exchanges, in request order.
func (r *Recorder) HTTP() []HTTPExchange {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]HTTPExchange, len(r.http))
	copy(out, r.http)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out
}

// Frames returns a copy of all recorded frames.
func (r *Recorder) Frames() []Frame {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Frame, len(r.frames))
	copy(out, r.frames)
	return out
}
