// Command sink is the Range's egress sink: an HTTP server on an internal-only
// network that records every request a target makes, so the oracle can see
// SSRF and exfiltration attempts (ADR-0010, design doc "oracle").
//
// It never forwards anything anywhere. Each response carries a per-run sink
// canary, so a target that relays fetched content back to the client is also
// caught by canary_leaked.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type entry struct {
	Time   string `json:"time"`
	Method string `json:"method"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	Query  string `json:"query"`
	Body   string `json:"body"`
}

func main() {
	addr := os.Getenv("SINK_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	logDir := os.Getenv("SINK_LOG_DIR")
	if logDir == "" {
		logDir = "/log"
	}
	f, err := os.OpenFile(filepath.Join(logDir, "requests.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o666)
	if err != nil {
		log.Fatal(err)
	}
	var mu sync.Mutex
	n := 0
	canary := os.Getenv("SINK_CANARY")
	h := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<10))
		mu.Lock()
		if n < 500 {
			n++
			b, _ := json.Marshal(entry{Time: time.Now().UTC().Format(time.RFC3339Nano), Method: r.Method,
				Host: trunc(r.Host, 256), Path: trunc(r.URL.Path, 1024), Query: trunc(r.URL.RawQuery, 1024), Body: trunc(string(body), 4096)})
			_, _ = f.Write(append(b, '\n'))
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "redfilade egress sink: request recorded. "+canary+"\n")
	}
	srv := &http.Server{Addr: addr, Handler: http.HandlerFunc(h), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Fatal(srv.ListenAndServe())
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
