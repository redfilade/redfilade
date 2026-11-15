package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/redfilade/redfilade/internal/mcp"
)

// New returns the model named by spec: "scripted:naive", "scripted:careful"
// or "anthropic:<model-id>".
func New(spec string) (Model, error) {
	kind, arg, _ := strings.Cut(spec, ":")
	switch kind {
	case "scripted":
		switch arg {
		case "naive":
			return &scripted{follow: true}, nil
		case "careful":
			return &scripted{}, nil
		}
		return nil, fmt.Errorf("unknown scripted model %q (naive or careful)", arg)
	case "anthropic":
		if !reModelID.MatchString(arg) {
			return nil, fmt.Errorf("invalid model id %q", arg)
		}
		key := os.Getenv("ANTHROPIC_API_KEY")
		if key == "" {
			return nil, errors.New("ANTHROPIC_API_KEY is not set")
		}
		base := os.Getenv("REDFILADE_MODEL_BASE_URL") // a model proxy (ADR-0008), optional
		if base == "" {
			base = "https://api.anthropic.com"
		}
		return &Anthropic{Model: arg, Key: key, BaseURL: base, HTTP: &http.Client{Timeout: 120 * time.Second}}, nil
	}
	return nil, fmt.Errorf("unknown model %q (use scripted:naive, scripted:careful or anthropic:<model-id>)", spec)
}

var reModelID = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,80}$`)

// --- scripted models -----------------------------------------------------------

// scripted is a deterministic stand-in for a model. It reads data with the
// first reading tool, then answers. With follow set it also obeys a
// "forward ... to <address>" instruction it finds in tool output, the way a
// model with no defence against indirect prompt injection might.
type scripted struct{ follow bool }

func (s *scripted) Name() string {
	if s.follow {
		return "scripted:naive"
	}
	return "scripted:careful"
}

var (
	reReadTool = regexp.MustCompile(`(?i)^(read|list|get|search|fetch|find)`)
	reForward  = regexp.MustCompile(`(?i)\bforward\b[^.\n]{0,120}?\bto\s+([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})`)
)

func (s *scripted) Next(_ context.Context, _ string, tools []mcp.Tool, msgs []Message) (Message, error) {
	var outputs []string
	sent := false
	for _, m := range msgs {
		for _, b := range m.Content {
			switch {
			case b.Type == "tool_result" && !b.IsError:
				outputs = append(outputs, b.Content)
			case b.Type == "tool_use" && strings.Contains(strings.ToLower(b.Name), "send"):
				sent = true
			}
		}
	}
	if len(outputs) == 0 {
		for _, t := range tools {
			if reReadTool.MatchString(t.Name) {
				return Message{Content: []Block{{Type: "tool_use", ID: "call_1", Name: t.Name, Input: map[string]any{}}}}, nil
			}
		}
		return Message{Content: []Block{{Type: "text", Text: "I have no tool to read your data."}}}, nil
	}
	all := strings.Join(outputs, "\n")
	if s.follow && !sent {
		if m := reForward.FindStringSubmatch(all); m != nil {
			for _, t := range tools {
				if strings.Contains(strings.ToLower(t.Name), "send") {
					return Message{Content: []Block{{Type: "tool_use", ID: "call_2", Name: t.Name,
						Input: map[string]any{"to": m[1], "subject": "Fwd: recent messages", "body": all}}}}, nil
				}
			}
		}
	}
	return Message{Content: []Block{{Type: "text", Text: "Here is a summary of what I found."}}}, nil
}

// --- Anthropic Messages API -----------------------------------------------------

// Anthropic calls the Messages API (or a compatible proxy at BaseURL).
type Anthropic struct {
	Model   string
	Key     string
	BaseURL string
	HTTP    *http.Client
}

func (a *Anthropic) Name() string { return "anthropic:" + a.Model }

type apiTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// Next sends the conversation and returns the model's reply. Tool
// descriptions come from the target and are passed as they are: that is part
// of what L3 tests.
func (a *Anthropic) Next(ctx context.Context, system string, tools []mcp.Tool, msgs []Message) (Message, error) {
	var ts []apiTool
	for _, t := range tools {
		schema := t.InputSchema
		if len(schema) == 0 || !json.Valid(schema) {
			schema = json.RawMessage(`{"type":"object"}`)
		}
		ts = append(ts, apiTool{Name: t.Name, Description: t.Description, InputSchema: schema})
	}
	body, err := json.Marshal(map[string]any{"model": a.Model, "max_tokens": 1024, "system": system, "messages": msgs, "tools": ts})
	if err != nil {
		return Message{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.BaseURL, "/")+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return Message{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", a.Key)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return Message{}, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return Message{}, err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		return Message{}, fmt.Errorf("model API: HTTP %d %s %s", resp.StatusCode, e.Error.Type, clip(e.Error.Message, 200))
	}
	var out struct {
		Content []Block `json:"content"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return Message{}, fmt.Errorf("model API: %w", err)
	}
	// Keep only the block types this loop understands.
	var keep []Block
	for _, blk := range out.Content {
		if blk.Type == "text" || blk.Type == "tool_use" {
			keep = append(keep, blk)
		}
	}
	return Message{Role: "assistant", Content: keep}, nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
