package mcpserver

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// Gate decides whether an HTTP request may reach the MCP handler. It returns
// 0 to allow, or an HTTP status to refuse with (and may set headers).
type Gate func(w http.ResponseWriter, r *http.Request, method, name string) int

// ServeHTTP serves MCP over Streamable HTTP (JSON responses) on addr until the
// process ends. gate runs before every request.
func ServeHTTP(addr, name string, tools []Tool, gate Gate) error {
	byName := map[string]Tool{}
	for _, t := range tools {
		byName[t.Name] = t
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		if json.Unmarshal(body, &req) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if gate != nil {
			if code := gate(w, r, req.Method, req.Params.Name); code != 0 {
				w.WriteHeader(code)
				return
			}
		}
		if len(req.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		var out bytes.Buffer
		handle(json.NewEncoder(&out), string(body), name, tools, byName)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out.Bytes())
	})
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, MaxHeaderBytes: 16 << 10}
	return srv.ListenAndServe()
}
