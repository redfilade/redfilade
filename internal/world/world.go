// Package world builds the synthetic organisation for one run (ADR-0014):
// fresh random canaries, rendered world files, and before/after hashes.
package world

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/redfilade/redfilade/internal/scenario"
)

// CanaryPrefix starts every canary value.
const CanaryPrefix = "CANARY_"

// World is the synthetic organisation for one run.
type World struct {
	// Root is a private (0700) directory owned by the CLI; Dir inside it is
	// the only path mounted into the cell.
	Root     string
	Dir      string
	Canaries map[string]string // name -> value, never written to logs
	Env      map[string]string // rendered needs.env for the cell
	before   map[string]string
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewCanary returns CANARY_<NAME>_<26 random base32 characters>.
func NewCanary(name string) (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return CanaryPrefix + name + "_" + b32.EncodeToString(buf), nil
}

// Build creates the world for m. Call Close when the run is over.
func Build(m *scenario.Manifest) (*World, error) {
	root, err := os.MkdirTemp("", "redfilade-run-")
	if err != nil {
		return nil, err
	}
	w := &World{Root: root, Dir: filepath.Join(root, "world"), Canaries: map[string]string{}, Env: map[string]string{}}
	if err := os.Chmod(root, 0o700); err != nil {
		w.Close()
		return nil, err
	}
	// The cell runs as an unprivileged user, so the world itself must be
	// writable by it; the 0700 parent keeps other host users out.
	if err := os.Mkdir(w.Dir, 0o777); err != nil {
		w.Close()
		return nil, err
	}
	_ = os.Chmod(w.Dir, 0o777)
	for name := range m.Canaries() {
		v, err := NewCanary(name)
		if err != nil {
			w.Close()
			return nil, err
		}
		w.Canaries[name] = v
	}
	for _, f := range m.World {
		dst := filepath.Join(w.Dir, filepath.FromSlash(f.Path))
		if !strings.HasPrefix(dst, w.Dir+string(os.PathSeparator)) {
			w.Close()
			return nil, fmt.Errorf("world path escapes the world: %q", f.Path)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o777); err != nil {
			w.Close()
			return nil, err
		}
		if err := os.WriteFile(dst, []byte(scenario.Render(f.Content, w.Canaries)), 0o666); err != nil {
			w.Close()
			return nil, err
		}
		_ = os.Chmod(dst, 0o666)
		_ = os.Chmod(filepath.Dir(dst), 0o777)
	}
	for _, e := range m.Needs.Env {
		w.Env[e.Name] = scenario.Render(e.Value, w.Canaries)
	}
	w.before, err = w.Snapshot()
	if err != nil {
		w.Close()
		return nil, err
	}
	return w, nil
}

// Snapshot hashes every regular file in the world.
func (w *World) Snapshot() (map[string]string, error) {
	out := map[string]string{}
	err := filepath.WalkDir(w.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			// A cell may plant symlinks; record them, never follow them.
			rel, _ := filepath.Rel(w.Dir, p)
			out[filepath.ToSlash(rel)] = "symlink"
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > 64<<20 {
			rel, _ := filepath.Rel(w.Dir, p)
			out[filepath.ToSlash(rel)] = fmt.Sprintf("oversized:%d", info.Size())
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		rel, _ := filepath.Rel(w.Dir, p)
		out[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	})
	return out, err
}

// Change is one difference between the world before and after the run.
type Change struct {
	Path   string `json:"path"`
	Change string `json:"change"` // "modified", "created", "deleted"
}

// Diff compares the world now with the snapshot taken at Build.
func (w *World) Diff() ([]Change, error) {
	after, err := w.Snapshot()
	if err != nil {
		return nil, err
	}
	var out []Change
	for p, h := range w.before {
		if a, ok := after[p]; !ok {
			out = append(out, Change{p, "deleted"})
		} else if a != h {
			out = append(out, Change{p, "modified"})
		}
	}
	for p := range after {
		if _, ok := w.before[p]; !ok {
			out = append(out, Change{p, "created"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// Redact replaces every canary value in s with its name.
func (w *World) Redact(s string) string {
	for name, v := range w.Canaries {
		s = strings.ReplaceAll(s, v, "[canary:"+name+"]")
	}
	return s
}

// Close removes the run's directory.
func (w *World) Close() { _ = os.RemoveAll(w.Root) }
