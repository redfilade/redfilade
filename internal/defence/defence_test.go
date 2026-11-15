package defence

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

type rule func(dir string, msg []byte) (bool, string)

func (r rule) Decide(dir string, msg []byte) (bool, string) { return r(dir, msg) }

func TestWrapBlocksBothWays(t *testing.T) {
	f := rule(func(dir string, msg []byte) (bool, string) {
		if dir == ClientToServer && strings.Contains(string(msg), "../") {
			return false, "path traversal"
		}
		if dir == ServerToClient && strings.Contains(string(msg), "SECRET") {
			return false, "secret in output"
		}
		return true, ""
	})
	targetOut, toClient := io.Pipe()  // what the target writes
	fromClient, targetIn := io.Pipe() // what reaches the target
	r, w, st := Wrap(f, targetOut, targetIn)
	reached := make(chan string, 4)
	go func() {
		sc := bufio.NewScanner(fromClient)
		for sc.Scan() {
			reached <- sc.Text()
		}
	}()
	lines := bufio.NewScanner(r)
	next := func() map[string]any {
		if !lines.Scan() {
			t.Fatal("no line")
		}
		var m map[string]any
		json.Unmarshal(lines.Bytes(), &m)
		return m
	}

	// A blocked request is answered locally with an error and never reaches the target.
	w.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_doc","arguments":{"name":"../x"}}}` + "\n"))
	if m := next(); m["error"] == nil || m["id"].(float64) != 1 {
		t.Fatalf("blocked request: %v", m)
	}
	// An allowed request reaches the target.
	w.Write([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n"))
	select {
	case got := <-reached:
		if !strings.Contains(got, `"id":2`) {
			t.Fatal(got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("allowed request never reached the target")
	}
	// A reply carrying a secret is replaced by an error.
	toClient.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"text":"SECRET=1"}}` + "\n"))
	if m := next(); m["error"] == nil || strings.Contains(lines.Text(), "SECRET=1") {
		t.Fatalf("blocked reply leaked: %s", lines.Text())
	}
	snap := st.Snapshot()
	if snap.Decisions != 3 || len(snap.Blocked) != 2 || snap.Blocked[0].Tool != "read_doc" {
		t.Fatalf("stats %+v", snap)
	}
}

func TestProcFailsClosed(t *testing.T) {
	// A defence that answers once, then garbage, then exits.
	defIn, defOut := io.Pipe()
	answers, writeAnswers := io.Pipe()
	p := NewProc(defOut, answers)
	go func() {
		sc := bufio.NewScanner(defIn)
		n := 0
		for sc.Scan() {
			n++
			switch n {
			case 1:
				writeAnswers.Write([]byte(`{"action":"allow"}` + "\n"))
			case 2:
				writeAnswers.Write([]byte(`{"action":"maybe"}` + "\n"))
			case 3:
				writeAnswers.Close()
			}
		}
	}()
	if ok, _ := p.Decide(ClientToServer, []byte(`{"id":1}`)); !ok {
		t.Fatal("first message should pass")
	}
	if ok, why := p.Decide(ClientToServer, []byte(`{"id":2}`)); ok || !strings.Contains(why, "invalid") {
		t.Fatalf("invalid answer must block: %v %q", ok, why)
	}
	if ok, why := p.Decide(ClientToServer, []byte(`{"id":3}`)); ok || !strings.Contains(why, "unavailable") {
		t.Fatalf("an exited defence must block: %v %q", ok, why)
	}
	if ok, _ := p.Decide(ClientToServer, []byte(`{"id":4}`)); ok {
		t.Fatal("a broken defence stays closed")
	}
}

func TestBenignSet(t *testing.T) {
	tasks, err := Benign()
	if err != nil || len(tasks) < 6 {
		t.Fatal(tasks, err)
	}
}
