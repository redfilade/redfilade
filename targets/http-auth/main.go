// Command http-auth is a Range target: an MCP server reached over Streamable
// HTTP that guards an account-lookup tool.
//
//	vulnerable: accepts any request, with or without a token; never rate
//	            limits; ignores the Mcp-Method and Mcp-Name headers
//	secure:     requires an HS256 JWT signed with JWT_SECRET whose audience is
//	            RESOURCE and which has not expired (401 with WWW-Authenticate
//	            otherwise); allows 10 requests per second per client (429 with
//	            Retry-After); rejects requests whose routing headers disagree
//	            with the body (400)
//
// Configuration comes from the environment: ADDR (default 127.0.0.1:8080),
// RESOURCE (the URL clients use) and JWT_SECRET. Deliberately vulnerable in
// its vulnerable build. Run it only in a Redfilade cell or on loopback.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/redfilade/redfilade/targets/internal/mcpserver"
)

var mode = "secure"

func main() {
	addr := envOr("ADDR", "127.0.0.1:8080")
	resource := envOr("RESOURCE", "http://"+addr+"/mcp")
	secret := os.Getenv("JWT_SECRET")
	tools := []mcpserver.Tool{{
		Name:        "get_account",
		Description: "Return the caller's account summary.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		Handle:      func(map[string]any) (string, bool) { return `{"account":"acme-001","plan":"team"}`, false },
	}}
	var gate mcpserver.Gate
	if mode != "vulnerable" {
		if len(secret) < 32 {
			log.Fatal("JWT_SECRET must be at least 32 bytes")
		}
		lim := &limiter{buckets: map[string]*bucket{}}
		gate = func(w http.ResponseWriter, r *http.Request, method, name string) int {
			if !lim.allow(clientKey(r)) {
				w.Header().Set("Retry-After", "1")
				return http.StatusTooManyRequests
			}
			if !validToken(r.Header.Get("Authorization"), secret, resource) {
				w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+resource+`/.well-known/oauth-protected-resource"`)
				return http.StatusUnauthorized
			}
			if r.Header.Get("MCP-Protocol-Version") == "2026-07-28" {
				if r.Header.Get("Mcp-Method") != method {
					return http.StatusBadRequest
				}
				needsName := method == "tools/call" || method == "resources/read" || method == "prompts/get"
				if needsName && r.Header.Get("Mcp-Name") != name {
					return http.StatusBadRequest
				}
			}
			return 0
		}
	}
	log.Fatal(mcpserver.ServeHTTP(addr, "redfilade-target-http-auth", tools, gate))
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// validToken checks an HS256 JWT: signature, expiry and audience.
func validToken(header, secret, resource string) bool {
	tok, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return false
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	enc := base64.RawURLEncoding
	hb, err1 := enc.DecodeString(parts[0])
	cb, err2 := enc.DecodeString(parts[1])
	sig, err3 := enc.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return false
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(hb, &h) != nil || h.Alg != "HS256" {
		return false // in particular, never accept "none"
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return false
	}
	var c struct {
		Aud any   `json:"aud"`
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(cb, &c) != nil || c.Exp <= time.Now().Unix() {
		return false
	}
	switch a := c.Aud.(type) {
	case string:
		return a == resource
	case []any:
		for _, x := range a {
			if x == resource {
				return true
			}
		}
	}
	return false
}

func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limiter is a token bucket per client: 10 requests, refilled at 10 per second.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: 10, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(10, b.tokens+now.Sub(b.last).Seconds()*10)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
