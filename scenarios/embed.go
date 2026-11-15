// Package scenarios embeds the Range's built-in scenarios into the binary.
//
// Built-in scenarios are trusted as part of the Redfilade release that
// contains them. Scenario packs loaded from a directory are not, and must be
// signed or explicitly allowed (internal/pack, architecture record 10.4).
package scenarios

import (
	"embed"
	"io/fs"
	"sort"

	"github.com/redfilade/redfilade/internal/scenario"
)

//go:embed */scenario.json
var files embed.FS

// Builtins returns every built-in scenario, sorted by id.
func Builtins() ([]*scenario.Manifest, error) {
	dirs, err := fs.Glob(files, "*/"+scenario.FileName)
	if err != nil {
		return nil, err
	}
	var out []*scenario.Manifest
	for _, f := range dirs {
		m, err := scenario.LoadFS(files, f[:len(f)-len("/"+scenario.FileName)])
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Builtin returns the built-in scenario with this id.
func Builtin(id string) (*scenario.Manifest, bool) {
	all, err := Builtins()
	if err != nil {
		return nil, false
	}
	for _, m := range all {
		if m.ID == id {
			return m, true
		}
	}
	return nil, false
}
