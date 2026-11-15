package mcp

// Streamable HTTP transport.
//
// The transport sits underneath the stdio-shaped Client: each line the client
// writes becomes one HTTP POST, and each JSON-RPC message in a response (a
// JSON body or Server-Sent Events) becomes one line the client reads. Every
// limit, the refusal of server-initiated requests and the frame recording
// therefore stay exactly as they are for stdio targets.
//
// For protocol 2026-07-28 every POST carries MCP-Protocol-Version, Mcp-Method
// and, for tools/call, resources/read and prompts/get, Mcp-Name. For
// 2025-11-25 the Mcp-Session-Id a server returns is echoed back.
//
// The server is hostile: redirects are never followed, response bodies are
// size-limited, and every exchange is logged with its HTTP status for the
// oracle.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Credentials a probe can send. "valid" sends the configured token, if any.
const (
	AuthValid      = "valid"
	AuthNone       = "none"
	AuthMalformed  = "malformed"
	AuthForgedNone = "forged-none"      // unsigned JWT (alg "none")
	AuthForgedSig  = "forged-signature" // JWT signed with a random key
	AuthForeign    = "foreign"          // a real token issued for another audience
)

// HTTPOptions configure the HTTP transport.
type HTTPOptions struct {
	URL          string
	Token        string // bearer token for the target, if it needs one
	ForeignToken string // a valid token issued for a different audience, optional
	HTTPClient   *http.Client
}

// HTTPTransport carries one Client's messages over Streamable HTTP.
type HTTPTransport struct {
	o      HTTPOptions
	c      *Client
	hc     *http.Client
	pw     *io.PipeWriter
	pwMu   sync.Mutex
	wg     sync.WaitGroup
	closed bool

	mu      sync.Mutex
	auth    string
	tag     string
	next    []func(*http.Request)
	session string
}

// DialHTTP returns a client that talks to the MCP server at o.URL.
func DialHTTP(o HTTPOptions, opts Options) (*Client, *HTTPTransport) {
	pr, pw := io.Pipe()
	t := &HTTPTransport{o: o, pw: pw, auth: AuthValid}
	t.hc = o.HTTPClient
	if t.hc == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		t.hc = &http.Client{Transport: tr}
	}
	// Never follow a redirect: a hostile server could bounce the client to
	// an internal address.
	hc := *t.hc
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	t.hc = &hc
	c := New(pr, t, opts)
	if t.hc.Timeout == 0 {
		t.hc.Timeout = c.opts.CallTimeout + 5*time.Second
	}
	t.c = c
	return c, t
}

// SetAuth chooses the credential sent with the following requests.
func (t *HTTPTransport) SetAuth(label string) {
	t.mu.Lock()
	t.auth = label
	t.mu.Unlock()
}

// SetTag labels the following requests in the HTTP log ("" to clear).
func (t *HTTPTransport) SetTag(tag string) {
	t.mu.Lock()
	t.tag = tag
	t.mu.Unlock()
}

// ModifyNext changes the next request only, after the standard headers are set.
func (t *HTTPTransport) ModifyNext(f func(*http.Request)) {
	t.mu.Lock()
	t.next = append(t.next, f)
	t.mu.Unlock()
}

// HasForeignToken reports whether a foreign-audience token was configured.
func (t *HTTPTransport) HasForeignToken() bool { return t.o.ForeignToken != "" }

// HasToken reports whether the target was given a token, meaning it is
// expected to require authentication.
func (t *HTTPTransport) HasToken() bool { return t.o.Token != "" }

// Close waits for requests in flight and ends the client's read loop.
func (t *HTTPTransport) Close() {
	t.wg.Wait()
	t.pwMu.Lock()
	t.closed = true
	_ = t.pw.Close()
	t.pwMu.Unlock()
}

// Write sends one JSON-RPC message (one line from the client) as a POST.
func (t *HTTPTransport) Write(p []byte) (int, error) {
	body := bytes.TrimRight(p, "\r\n")
	var m struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name string `json:"name"`
			URI  string `json:"uri"`
		} `json:"params"`
	}
	_ = json.Unmarshal(body, &m)
	name := ""
	switch m.Method {
	case "tools/call", "prompts/get":
		name = m.Params.Name
	case "resources/read":
		name = m.Params.URI
	}

	t.mu.Lock()
	auth, tag, mods, session := t.auth, t.tag, t.next, t.session
	t.next = nil
	t.mu.Unlock()

	req, err := http.NewRequest(http.MethodPost, t.o.URL, bytes.NewReader(append([]byte(nil), body...)))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", t.c.opts.Protocol)
	if t.c.opts.Protocol == Protocol2026 {
		if m.Method != "" {
			req.Header.Set("Mcp-Method", m.Method)
		}
		if name != "" {
			req.Header.Set("Mcp-Name", name)
		}
	} else if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	if v := t.credential(auth); v != "" {
		req.Header.Set("Authorization", "Bearer "+v)
	}
	for _, f := range mods {
		f(req)
	}
	ex := HTTPExchange{Seq: t.c.rec.lastSeq(), Method: m.Method, Name: name, Auth: auth, Tag: tag}
	t.wg.Add(1)
	go t.do(req, m.ID, ex)
	return len(p), nil
}

func (t *HTTPTransport) credential(label string) string {
	switch label {
	case AuthValid:
		return t.o.Token
	case AuthMalformed:
		return "redfilade-malformed-token"
	case AuthForgedNone:
		return forgedJWT(t.o.URL, false)
	case AuthForgedSig:
		return forgedJWT(t.o.URL, true)
	case AuthForeign:
		return t.o.ForeignToken
	default:
		return ""
	}
}

// forgedJWT builds a token that looks right (audience, issuer, expiry) but is
// unsigned or signed with a random key, so no correct server can accept it.
func forgedJWT(aud string, signed bool) string {
	enc := base64.RawURLEncoding
	alg := "none"
	if signed {
		alg = "HS256"
	}
	h, _ := json.Marshal(map[string]any{"alg": alg, "typ": "JWT"})
	now := time.Now().Unix()
	c, _ := json.Marshal(map[string]any{"iss": "https://redfilade.invalid", "sub": "redfilade-probe", "aud": aud, "iat": now, "exp": now + 300})
	unsigned := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	if !signed {
		return unsigned + "."
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(unsigned))
	return unsigned + "." + enc.EncodeToString(mac.Sum(nil))
}

func (t *HTTPTransport) do(req *http.Request, id json.RawMessage, ex HTTPExchange) {
	defer t.wg.Done()
	start := t.c.rec.since()
	ex.OffsetMS = start.Milliseconds()
	ex.Outcome = "none"
	defer func() {
		ex.DurationMS = (t.c.rec.since() - start).Milliseconds()
		t.c.rec.addHTTP(ex)
	}()
	fail := func(msg string) {
		if len(id) > 0 {
			t.c.deliver(id, &message{ID: id, Error: &RPCError{Code: -32099, Message: msg}})
		}
	}

	resp, err := t.hc.Do(req.WithContext(context.Background()))
	if err != nil {
		ex.Outcome = "transport-error"
		fail("http request failed: " + err.Error())
		return
	}
	defer resp.Body.Close()
	ex.Status = resp.StatusCode
	ex.RetryAfter = clip(resp.Header.Get("Retry-After"), 64)
	ex.WWWAuthenticate = clip(resp.Header.Get("WWW-Authenticate"), 300)
	if s := resp.Header.Get("Mcp-Session-Id"); s != "" && t.c.opts.Protocol != Protocol2026 {
		t.mu.Lock()
		t.session = clip(s, 256)
		t.mu.Unlock()
	}
	limit := int64(t.c.opts.MaxMessageBytes)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, limit))
		fail(fmt.Sprintf("HTTP %d %s", resp.StatusCode, http.StatusText(resp.StatusCode)))
		return
	}
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	var msgs [][]byte
	switch ct {
	case "text/event-stream":
		msgs, err = readSSE(resp.Body, limit)
	default:
		var b []byte
		b, err = io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err == nil && int64(len(b)) > limit {
			err = ErrMessageTooLarge
		}
		if len(bytes.TrimSpace(b)) > 0 {
			msgs = [][]byte{b}
		}
	}
	for _, b := range msgs {
		line := oneLine(b)
		var r struct {
			ID     json.RawMessage `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if json.Unmarshal(line, &r) == nil && bytes.Equal(r.ID, id) {
			switch {
			case len(r.Result) > 0:
				ex.Outcome = "result"
			case len(r.Error) > 0:
				ex.Outcome = "error"
			}
		}
		t.pwMu.Lock()
		if !t.closed {
			_, _ = t.pw.Write(append(line, '\n'))
		}
		t.pwMu.Unlock()
	}
	if err != nil {
		fail("http response: " + err.Error())
		return
	}
	if ex.Outcome == "none" && len(id) > 0 {
		fail("http response carried no reply for this request")
	}
}

// oneLine makes a message fit the line framing: valid JSON is compacted,
// anything else has its line breaks replaced so it is recorded as one frame.
func oneLine(b []byte) []byte {
	var buf bytes.Buffer
	if json.Compact(&buf, b) == nil {
		return buf.Bytes()
	}
	return bytes.ReplaceAll(bytes.ReplaceAll(b, []byte("\r"), []byte(" ")), []byte("\n"), []byte(" "))
}

// readSSE returns the data of each event, joining multi-line data fields.
func readSSE(r io.Reader, limit int64) ([][]byte, error) {
	var out [][]byte
	var cur []byte
	var total int64
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), int(limit)+1)
	flush := func() {
		if len(cur) > 0 {
			out = append(out, cur)
			cur = nil
		}
	}
	for sc.Scan() {
		line := sc.Text()
		total += int64(len(line)) + 1
		if total > limit {
			return out, ErrMessageTooLarge
		}
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "data:"):
			d := strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")
			if len(cur) > 0 {
				cur = append(cur, '\n')
			}
			cur = append(cur, d...)
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return out, ErrMessageTooLarge
		}
		return out, err
	}
	return out, nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
