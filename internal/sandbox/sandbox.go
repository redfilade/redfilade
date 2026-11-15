// Package sandbox runs a target in a hardened container cell (ADR-0015).
//
// The cell never gets the user's home folder, SSH or cloud keys, the Docker
// socket, the host network or the host environment. Its only mount is the
// run's own world directory.
package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
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
	if net == "host" || net == "bridge" || strings.HasPrefix(net, "container:") {
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
