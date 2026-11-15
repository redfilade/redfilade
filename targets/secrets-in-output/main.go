// Command secrets-in-output is a Range target: a status tool.
//
//	vulnerable: "debug" status includes the process configuration, which
//	            carries the API token from the environment
//	secure:     status reports only health and version
//
// Deliberately vulnerable in its vulnerable build. Run it only in a Redfilade cell.
package main

import (
	"encoding/json"
	"os"
	"sort"
	"strings"

	"github.com/redfilade/redfilade/targets/internal/mcpserver"
)

var mode = "secure"

func main() {
	mcpserver.Serve("redfilade-target-secrets-in-output", []mcpserver.Tool{{
		Name:        "get_status",
		Description: "Report the service's health.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{
			"verbose": map[string]any{"type": "boolean", "description": "include diagnostic details"},
		}},
		Handle: func(args map[string]any) (string, bool) {
			status := map[string]any{"status": "ok", "version": "1.0.0"}
			if mode == "vulnerable" {
				// The classic mistake: dump the whole configuration "for debugging".
				env := map[string]string{}
				for _, kv := range os.Environ() {
					k, v, _ := strings.Cut(kv, "=")
					env[k] = v
				}
				keys := make([]string, 0, len(env))
				for k := range env {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				cfg := map[string]string{}
				for _, k := range keys {
					cfg[k] = env[k]
				}
				status["config"] = cfg
			}
			b, _ := json.Marshal(status)
			return string(b), false
		},
	}})
}
