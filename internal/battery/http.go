package battery

// L2 attacks that need Streamable HTTP: authentication, rate limiting and the
// 2026-07-28 routing headers. They send only tools/list and one harmless
// tools/call; nothing is written.

import (
	"context"
	"net/http"
	"sync"

	"github.com/redfilade/redfilade/internal/mcp"
	"github.com/redfilade/redfilade/internal/scenario"
)

// BurstSize is how many requests the rate-limit probe sends. It stays small
// on purpose: enough to see a limit, not enough to load a server.
const BurstSize = 40

func init() {
	register(Attack{
		ID: "l2-token-audience", Level: "L2", Family: "01", HTTPOnly: true, Remote: true,
		Title:   "Requests without a valid token for this server are accepted",
		Checks:  []scenario.Check{{Fact: "auth_bypassed"}},
		Network: "none",
		Run:     tokenAudience,
	})
	register(Attack{
		ID: "l2-rate-limit", Level: "L2", Family: "09", HTTPOnly: true, Remote: true,
		Title:   "No rate limit: a burst of requests is served in full",
		Checks:  []scenario.Check{{Fact: "rate_limit_missing"}},
		Network: "none",
		Run:     rateLimit,
	})
	register(Attack{
		ID: "l2-header-mismatch", Level: "L2", Family: "10", HTTPOnly: true, Remote: true,
		Title:   "Routing headers that disagree with the body are accepted",
		Checks:  []scenario.Check{{Fact: "header_mismatch_accepted"}},
		Network: "none",
		Run:     headerMismatch,
	})
}

// tokenAudience only runs when the server is meant to be protected, that is
// when the builder supplied a token for it.
func tokenAudience(ctx context.Context, c *mcp.Client, _ []mcp.Tool, env Env) error {
	t := env.HTTP
	if t == nil || !t.HasToken() {
		return nil
	}
	defer t.SetAuth(mcp.AuthValid)
	defer t.SetTag("")
	labels := []string{mcp.AuthNone, mcp.AuthMalformed, mcp.AuthForgedNone, mcp.AuthForgedSig}
	if t.HasForeignToken() {
		labels = append(labels, mcp.AuthForeign)
	}
	for _, l := range labels {
		t.SetAuth(l)
		t.SetTag("auth")
		_, _ = c.Call(ctx, "tools/list", nil) // a refusal is the expected answer
	}
	return nil
}

func rateLimit(ctx context.Context, c *mcp.Client, _ []mcp.Tool, env Env) error {
	t := env.HTTP
	if t == nil {
		return nil
	}
	t.SetTag("burst")
	defer t.SetTag("")
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i := 0; i < BurstSize; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			_, _ = c.Call(ctx, "tools/list", nil)
		}()
	}
	wg.Wait()
	return nil
}

func headerMismatch(ctx context.Context, c *mcp.Client, tools []mcp.Tool, env Env) error {
	t := env.HTTP
	if t == nil || c.Protocol() != mcp.Protocol2026 || len(tools) == 0 {
		return nil
	}
	tool := tools[0]
	args := minimalArgs(parseSchema(tool.InputSchema))
	t.SetTag("mismatch")
	defer t.SetTag("")
	// The body calls a real tool while the headers claim something harmless.
	t.ModifyNext(func(r *http.Request) { r.Header.Set("Mcp-Name", "redfilade_harmless_tool") })
	_, _ = c.CallTool(ctx, tool.Name, args)
	t.ModifyNext(func(r *http.Request) { r.Header.Set("Mcp-Method", "tools/list"); r.Header.Del("Mcp-Name") })
	_, _ = c.CallTool(ctx, tool.Name, args)
	return nil
}

// RemoteRequestBudget is an upper bound on the requests a remote run at this
// level sends, shown on the consent screen. It assumes the worst case: the
// maximum number of probed tools, each with three matching parameters.
func RemoteRequestBudget(level string) int {
	n := 2 // discovery and tools/list
	for _, a := range ForLevel(level) {
		if !a.Remote {
			continue
		}
		switch a.ID {
		case "l1-leaky-errors":
			n += 1 + maxToolsProbed*4
		case "l2-sql-injection":
			n += maxToolsProbed * 3 * len(sqlPayloads)
		case "l2-token-audience":
			n += 5
		case "l2-rate-limit":
			n += BurstSize
		case "l2-header-mismatch":
			n += 2
		}
	}
	return n
}
