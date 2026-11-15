package world

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/redfilade/redfilade/internal/scenario"
)

func manifest() *scenario.Manifest {
	return &scenario.Manifest{
		World: []scenario.File{{Path: "config/app.env", Content: "DB={{canary.DB}}\n"}},
		Needs: scenario.Needs{Env: []scenario.EnvVar{{Name: "TOKEN", Value: "{{canary.TOKEN}}"}}},
	}
}

func TestBuildPlantsFreshCanaries(t *testing.T) {
	a, err := Build(manifest())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Build(manifest())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	re := regexp.MustCompile(`^CANARY_DB_[A-Z2-7]{26}$`)
	if !re.MatchString(a.Canaries["DB"]) {
		t.Fatalf("canary format: %q", a.Canaries["DB"])
	}
	if a.Canaries["DB"] == b.Canaries["DB"] {
		t.Fatal("canaries repeat across runs")
	}
	content, _ := os.ReadFile(filepath.Join(a.Dir, "config/app.env"))
	if !strings.Contains(string(content), a.Canaries["DB"]) {
		t.Fatal("canary not rendered into world file")
	}
	if a.Env["TOKEN"] != a.Canaries["TOKEN"] {
		t.Fatal("env canary not rendered")
	}
	st, _ := os.Stat(a.Root)
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("run root mode = %v, want 0700", st.Mode().Perm())
	}
}

func TestDiffAndRedact(t *testing.T) {
	w, err := Build(manifest())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if d, _ := w.Diff(); len(d) != 0 {
		t.Fatalf("fresh world has changes: %v", d)
	}
	_ = os.WriteFile(filepath.Join(w.Dir, "config/app.env"), []byte("tampered"), 0o666)
	_ = os.WriteFile(filepath.Join(w.Dir, "dropped.sh"), []byte("x"), 0o666)
	_ = os.Symlink("/etc/passwd", filepath.Join(w.Dir, "link"))
	d, err := w.Diff()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"config/app.env": "modified", "dropped.sh": "created", "link": "created"}
	if len(d) != len(want) {
		t.Fatalf("diff = %v", d)
	}
	for _, c := range d {
		if want[c.Path] != c.Change {
			t.Errorf("%s: %s, want %s", c.Path, c.Change, want[c.Path])
		}
	}
	if got := w.Redact("leak " + w.Canaries["DB"]); got != "leak [canary:DB]" {
		t.Fatalf("redact = %q", got)
	}
}
