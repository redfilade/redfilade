// Package sandbox runs a target in a hardened container cell (ADR-0015).
//
// The cell never gets the user's home folder, SSH or cloud keys, the Docker
// socket, the host network or the host environment. Its only mount is the
// run's own world directory.
package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Tier is the isolation strength available on this machine.
type Tier string

// Isolation tiers, strongest first.
const (
	TierGVisor Tier = "gvisor"
	TierDocker Tier = "docker"
	TierNone   Tier = "none"
)

// WorldMount is where the world appears inside the cell.
const WorldMount = "/world"

// Spec describes one cell.
type Spec struct {
	Name     string            // unique container name
	Image    string            // target image
	Cmd      []string          // optional command
	WorldDir string            // host path mounted at /world
	Network  string            // "none" or the name of an internal sink network
	Env      map[string]string // only these variables are set
	Tier     Tier
	Pull     string // "never" (default, locally built twins) or "missing"
}

// reRunNetwork matches the per-run internal networks this package creates.
var reRunNetwork = regexp.MustCompile(`^redfilade-net-[0-9a-f]{8,32}$`)

// Egress sink settings (ADR-0010: no route to the internet, ever).
const (
	SinkImage = "redfilade-infra/sink:latest"
	SinkHost  = "sink.redfilade.test"
	SinkPort  = "8080"
)

// Docker resource limits for every cell.
const (
	memoryLimit = "256m"
	cpuLimit    = "1"
	pidsLimit   = "128"
	tmpfsSpec   = "/tmp:rw,noexec,nosuid,nodev,size=16m"
	cellUser    = "65532:65532"
)

// Args returns the full `docker run` argument list for spec.
func Args(s Spec) ([]string, error) {
	if s.Image == "" || strings.HasPrefix(s.Image, "-") {
		return nil, errors.New("sandbox: invalid image")
	}
	if s.Name == "" || strings.HasPrefix(s.Name, "-") {
		return nil, errors.New("sandbox: invalid name")
	}
	net := s.Network
	if net == "" {
		net = "none"
	}
	if net != "none" && !reRunNetwork.MatchString(net) {
		return nil, fmt.Errorf("sandbox: network %q is never allowed", net)
	}
	pull := s.Pull
	if pull == "" {
		pull = "never"
	}
	if pull != "never" && pull != "missing" {
		return nil, fmt.Errorf("sandbox: pull policy %q not allowed", pull)
	}
	a := []string{"run", "--rm", "-i",
		"--name", s.Name,
		"--network", net,
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--user", cellUser,
		"--memory", memoryLimit, "--memory-swap", memoryLimit,
		"--cpus", cpuLimit,
		"--pids-limit", pidsLimit,
		"--tmpfs", tmpfsSpec,
		"--ipc", "none",
		"--log-driver", "none",
		"--pull", pull,
		"--label", "io.redfilade.cell=1",
	}
	if s.Tier == TierGVisor {
		a = append(a, "--runtime", "runsc")
	}
	if s.WorldDir != "" {
		if strings.ContainsAny(s.WorldDir, ",=") {
			return nil, errors.New("sandbox: world path contains unsafe characters")
		}
		a = append(a, "--mount", "type=bind,src="+s.WorldDir+",dst="+WorldMount)
	}
	for k, v := range s.Env {
		a = append(a, "--env", k+"="+v)
	}
	a = append(a, "--", s.Image)
	a = append(a, s.Cmd...)
	return a, nil
}

// Runner starts cells with a container CLI (docker, or a compatible one).
type Runner struct {
	Binary string // "docker" by default
}

func (r Runner) bin() string {
	if r.Binary == "" {
		return "docker"
	}
	return r.Binary
}

// DetectTier reports the strongest isolation available.
func (r Runner) DetectTier(ctx context.Context) Tier {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, r.bin(), "info", "--format", "{{json .Runtimes}}").Output()
	if err != nil {
		return TierNone
	}
	if bytes.Contains(out, []byte(`"runsc"`)) {
		return TierGVisor
	}
	return TierDocker
}

// Cell is a running target.
type Cell struct {
	Stdin  io.WriteCloser
	Stdout io.Reader
	cmd    *exec.Cmd
	name   string
	runner Runner
	stderr *capped
	once   sync.Once
}

// Start launches the cell. The host environment is not passed to docker's
// child process beyond what docker itself needs.
func (r Runner) Start(ctx context.Context, s Spec) (*Cell, error) {
	args, err := Args(s)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, r.bin(), args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	errBuf := &capped{limit: 64 << 10}
	cmd.Stderr = errBuf
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &Cell{Stdin: stdin, Stdout: stdout, cmd: cmd, name: s.Name, runner: r, stderr: errBuf}, nil
}

// Stop closes the cell's input and removes the container.
func (c *Cell) Stop() {
	c.once.Do(func() {
		_ = c.Stdin.Close()
		done := make(chan struct{})
		go func() { _ = c.cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = exec.CommandContext(ctx, c.runner.bin(), "rm", "-f", c.name).Run()
			<-done
		}
	})
}

// Stderr returns up to 64 KiB of the cell's standard error.
func (c *Cell) Stderr() string { return c.stderr.String() }

type capped struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	limit int
}

func (c *capped) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.limit - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

func (c *capped) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// Sink is a running egress sink on a per-run internal network.
type Sink struct {
	Network string
	name    string
	logDir  string
	runner  Runner
}

// SinkEvent is one request the sink recorded.
type SinkEvent struct {
	Method string `json:"method"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	Query  string `json:"query"`
	Body   string `json:"body"`
}

// StartSink creates an internal network (no external route) and starts the
// sink on it under the name sink.redfilade.test. logDir must be a private
// directory owned by the run.
func (r Runner) StartSink(ctx context.Context, runID, logDir, canary string, tier Tier) (*Sink, error) {
	netName := "redfilade-net-" + runID
	if !reRunNetwork.MatchString(netName) {
		return nil, errors.New("sandbox: invalid run id for network")
	}
	if strings.ContainsAny(logDir, ",=") {
		return nil, errors.New("sandbox: sink log path contains unsafe characters")
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(cctx, r.bin(), "network", "create", "--internal", "--label", "io.redfilade.cell=1", netName).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("sandbox: create internal network: %v: %s", err, bytes.TrimSpace(out))
	}
	s := &Sink{Network: netName, name: "redfilade-sink-" + runID, logDir: logDir, runner: r}
	args := []string{"run", "-d", "--rm", "--name", s.name,
		"--network", netName, "--network-alias", SinkHost,
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", cellUser,
		"--memory", "64m", "--memory-swap", "64m", "--cpus", "0.5", "--pids-limit", "32",
		"--ipc", "none", "--log-driver", "none", "--pull", "never", "--label", "io.redfilade.cell=1",
		"--mount", "type=bind,src=" + logDir + ",dst=/log",
		"--env", "SINK_CANARY=" + canary}
	if tier == TierGVisor {
		args = append(args, "--runtime", "runsc")
	}
	args = append(args, "--", SinkImage)
	if out, err := exec.CommandContext(cctx, r.bin(), args...).CombinedOutput(); err != nil {
		s.Stop()
		return nil, fmt.Errorf("sandbox: start sink: %v: %s", err, bytes.TrimSpace(out))
	}
	// Give the sink a moment to bind before the target starts.
	time.Sleep(500 * time.Millisecond)
	return s, nil
}

// Stop removes the sink and its network.
func (s *Sink) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, s.runner.bin(), "rm", "-f", s.name).Run()
	_ = exec.CommandContext(ctx, s.runner.bin(), "network", "rm", s.Network).Run()
}

// Events reads what the sink recorded (bounded: 500 events, 2 MiB).
func (s *Sink) Events() ([]SinkEvent, error) {
	f, err := os.Open(filepath.Join(s.logDir, "requests.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []SinkEvent
	sc := bufio.NewScanner(io.LimitReader(f, 2<<20))
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() && len(out) < 500 {
		var e SinkEvent
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			out = append(out, e)
		}
	}
	return out, nil
}
