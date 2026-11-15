package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/redfilade/redfilade/internal/sandbox"
)

// TestHostileServerAgainstClientTwins connects `redfilade hostile-server` to
// each client twin exactly as a real client would launch a stdio server, then
// judges the saved session with `redfilade client-report`.
func TestHostileServerAgainstClientTwins(t *testing.T) {
	root, _ := filepath.Abs("../..")
	for _, mode := range []string{"vulnerable", "secure"} {
		bin := filepath.Join(t.TempDir(), "client-"+mode)
		b := exec.Command("go", "build", "-ldflags", "-X main.mode="+mode, "-o", bin, "./targets/mcp-client")
		b.Dir = root
		if out, err := b.CombinedOutput(); err != nil {
			t.Fatalf("build: %v\n%s", err, out)
		}
		client := exec.Command(bin)
		client.Env = []string{"USER_PASSWORD=REDFILADE_TEST_PASSWORD_NOT_A_SECRET"}
		toClient, _ := client.StdinPipe()
		fromClient, _ := client.StdoutPipe()
		if err := client.Start(); err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		log := filepath.Join(dir, "session.jsonl")
		var stderr bytes.Buffer
		code := Main(context.Background(), []string{"hostile-server", "--log", log, "--idle", "5s"}, fromClient, toClient, &stderr, sandbox.Runner{})
		toClient.Close()
		_ = client.Wait()
		if code != exitPass {
			t.Fatalf("%s: hostile-server exit %d: %s", mode, code, stderr.String())
		}
		var out bytes.Buffer
		code = Main(context.Background(), []string{"client-report", log, "--out", dir, "--sarif", filepath.Join(dir, "c.sarif")},
			strings.NewReader(""), &out, &stderr, sandbox.Runner{})
		ev, _ := os.ReadFile(filepath.Join(dir, "evidence-client-L4.json"))
		switch mode {
		case "vulnerable":
			if code != exitFindings {
				t.Fatalf("vulnerable client: exit %d\n%s", code, out.String())
			}
			for _, f := range []string{"client_followed_hidden_instruction", "client_answered_elicitation", "client_answered_sampling"} {
				if !strings.Contains(string(ev), f) {
					t.Errorf("vulnerable client should show %s\n%s", f, out.String())
				}
			}
		case "secure":
			if code != exitPass {
				t.Fatalf("secure client: exit %d\n%s\n%s", code, out.String(), ev)
			}
		}
	}
	var out, errb bytes.Buffer
	if code := Main(context.Background(), []string{"client-report", filepath.Join(t.TempDir(), "missing.jsonl")}, strings.NewReader(""), &out, &errb, sandbox.Runner{}); code != exitError {
		t.Errorf("missing log: exit %d", code)
	}
}
