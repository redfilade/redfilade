// Command ssrf is a Range target: a link-preview tool.
//
//	vulnerable: fetches any URL it is given, including internal and
//	            metadata addresses, and returns the start of the response
//	secure:     only fetches https URLs on an allow-listed host and never
//	            follows redirects
//
// Deliberately vulnerable in its vulnerable build. Run it only in a Redfilade cell.
package main

import (
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/redfilade/redfilade/targets/internal/mcpserver"
)

var mode = "secure"

// allowed is the only host the secure build will contact.
var allowed = map[string]bool{"docs.example.com": true}

func main() {
	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	mcpserver.Serve("redfilade-target-ssrf", []mcpserver.Tool{{
		Name:        "fetch_preview",
		Description: "Fetch a web page and return a short preview of it.",
		InputSchema: map[string]any{"type": "object", "required": []string{"url"},
			"properties": map[string]any{"url": map[string]any{"type": "string", "format": "uri"}}},
		Handle: func(args map[string]any) (string, bool) {
			raw, _ := mcpserver.Str(args, "url")
			u, err := url.Parse(raw)
			if err != nil || u.Host == "" {
				return "Please provide a full URL.", true
			}
			if mode != "vulnerable" {
				if u.Scheme != "https" || !allowed[u.Hostname()] || u.User != nil || u.Port() != "" {
					return "Previews are only available for https://docs.example.com.", true
				}
			}
			resp, err := client.Get(u.String())
			if err != nil {
				if mode == "vulnerable" {
					return "fetch failed: " + err.Error(), true
				}
				return "The page could not be fetched.", true
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
			return "Preview: " + string(b), false
		},
	}})
}
