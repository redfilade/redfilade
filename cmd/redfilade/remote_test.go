package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/redfilade/redfilade/internal/sandbox"
)

func mintJWT(t *testing.T, secret, aud string) string {
	t.Helper()
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
	c, _ := json.Marshal(map[string]any{"sub": "builder", "aud": aud, "exp": time.Now().Add(time.Hour).Unix()})
	unsigned := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(unsigned))
	return unsigned + "." + enc.EncodeToString(mac.Sum(nil))
}

// startHTTPTwin builds and runs the http-auth twin on a free loopback port.
func startHTTPTwin(t *testing.T, mode, secret string) string {
	t.Helper()
	root, _ := filepath.Abs("../..")
	bin := filepath.Join(t.TempDir(), "http-auth-"+mode)
	b := exec.Command("go", "build", "-ldflags", "-X main.mode="+mode, "-o", bin, "./targets/http-auth")
	b.Dir = root
	if out, err := b.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	url := "http://" + addr + "/mcp"
	cmd := exec.Command(bin)
	cmd.Env = []string{"ADDR=" + addr, "RESOURCE=" + url, "JWT_SECRET=" + secret}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return url
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("twin did not start")
	return ""
}

func TestRemoteHTTPEndToEnd(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	secret := hex.EncodeToString(key)
	for _, mode := range []string{"vulnerable", "secure"} {
		url := startHTTPTwin(t, mode, secret)
		t.Setenv("REDFILADE_TEST_TOKEN", mintJWT(t, secret, url))
		t.Setenv("REDFILADE_TEST_FOREIGN", mintJWT(t, secret, "https://other-server.example/mcp"))
		out := t.TempDir()
		var stdout, stderr bytes.Buffer
		code := Main(context.Background(), []string{"test", "--url", url, "--level", "L2", "--yes", "--out", out,
			"--token-env", "REDFILADE_TEST_TOKEN", "--foreign-token-env", "REDFILADE_TEST_FOREIGN",
			"--sarif", filepath.Join(out, "r.sarif")}, strings.NewReader(""), &stdout, &stderr, sandbox.Runner{})
		ev, _ := os.ReadFile(filepath.Join(out, "evidence-test-L2.json"))
		switch mode {
		case "vulnerable":
			if code != exitFindings {
				t.Fatalf("vulnerable: exit %d\n%s%s", code, stdout.String(), stderr.String())
			}
			for _, fact := range []string{"auth_bypassed", "rate_limit_missing", "header_mismatch_accepted"} {
				if !strings.Contains(string(ev), `"fact": "`+fact+`"`) {
					t.Errorf("vulnerable twin should show %s\n%s", fact, stdout.String())
				}
			}
			sarif, _ := os.ReadFile(filepath.Join(out, "r.sarif"))
			if !strings.Contains(string(sarif), "RF-AUTH-BYPASS") {
				t.Error("SARIF should carry the auth rule")
			}
		case "secure":
			if code != exitPass {
				t.Fatalf("secure: exit %d\n%s%s\n%s", code, stdout.String(), stderr.String(), ev)
			}
		}
		if strings.Contains(string(ev), os.Getenv("REDFILADE_TEST_TOKEN")) || strings.Contains(string(ev), os.Getenv("REDFILADE_TEST_FOREIGN")) {
			t.Errorf("%s: evidence contains a raw token", mode)
		}
		if !strings.Contains(stdout.String(), "loopback") {
			t.Errorf("consent screen should say why the host is allowed:\n%s", stdout.String())
		}
	}
}

func TestRemoteRefusesNonLoopback(t *testing.T) {
	for _, u := range []string{"https://example.com/mcp", "http://10.0.0.5/mcp", "http://localhost.evil.test/mcp", "ftp://127.0.0.1/", "http://user:pw@127.0.0.1/"} {
		var stdout, stderr bytes.Buffer
		code := Main(context.Background(), []string{"test", "--url", u, "--yes"}, strings.NewReader(""), &stdout, &stderr, sandbox.Runner{})
		if code != exitError {
			t.Errorf("%s: exit %d", u, code)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := Main(context.Background(), []string{"test", "--url", "http://127.0.0.1:1/mcp", "--image", "x", "--yes"}, strings.NewReader(""), &stdout, &stderr, sandbox.Runner{}); code != exitError {
		t.Errorf("--url with --image: exit %d", code)
	}
	if code := Main(context.Background(), []string{"test", "--url", "http://127.0.0.1:1/mcp", "--token-env", "REDFILADE_NO_SUCH_VAR", "--yes"}, strings.NewReader(""), &stdout, &stderr, sandbox.Runner{}); code != exitError {
		t.Errorf("missing token variable: exit %d", code)
	}
}

// keep imports used on all platforms
var _ = strconv.Itoa
var _ = http.StatusOK
