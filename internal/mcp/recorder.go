package mcp

import (
	"encoding/json"
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
	limit  int
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

// Frames returns a copy of all recorded frames.
func (r *Recorder) Frames() []Frame {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Frame, len(r.frames))
	copy(out, r.frames)
	return out
}
