package scenarios

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuiltinsMatchDirectories(t *testing.T) {
	all, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	dirs, _ := filepath.Glob("*/scenario.json")
	if len(all) != len(dirs) || len(all) < 4 {
		t.Fatalf("embedded %d scenarios, found %d directories", len(all), len(dirs))
	}
	for _, m := range all {
		if _, err := os.Stat(filepath.Join(m.ID, "scenario.json")); err != nil {
			t.Errorf("scenario id %q must match its directory name", m.ID)
		}
		if m.Kind == "attack" && m.Builds.Vulnerable.Image == m.Builds.Secure.Image {
			t.Errorf("%s: twins share an image", m.ID)
		}
	}
	if _, ok := Builtin("l2-ssrf"); !ok {
		t.Fatal("l2-ssrf not found")
	}
}
