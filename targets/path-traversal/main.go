// Command path-traversal is a Range target: a document reader and note writer.
//
//	vulnerable: joins the user's name onto the base directory without checks,
//	            so "../" escapes it (read and write)
//	secure:     resolves the path and rejects anything outside the base
//	            directory, absolute paths and encoded separators
//
// Deliberately vulnerable in its vulnerable build. Run it only in a Redfilade cell.
package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/redfilade/redfilade/targets/internal/mcpserver"
)

var mode = "secure"

func docsDir() string  { return filepath.Join(mcpserver.WorldDir(), "docs") }
func notesDir() string { return filepath.Join(mcpserver.WorldDir(), "notes") }

// resolve maps a user-supplied name into base. The two builds differ here only.
func resolve(base, name string) (string, bool) {
	if mode == "vulnerable" {
		return filepath.Join(base, name), true // "../" walks right out of base
	}
	if name == "" || len(name) > 64 || filepath.IsAbs(name) || strings.ContainsAny(name, `\%`) {
		return "", false
	}
	p := filepath.Join(base, filepath.Clean("/"+name))
	if p != base && !strings.HasPrefix(p, base+string(os.PathSeparator)) {
		return "", false
	}
	// Refuse symlinks that point elsewhere.
	if real, err := filepath.EvalSymlinks(p); err == nil && !strings.HasPrefix(real, base+string(os.PathSeparator)) {
		return "", false
	}
	return p, true
}

func main() {
	mcpserver.Serve("redfilade-target-path-traversal", []mcpserver.Tool{
		{
			Name:        "read_doc",
			Description: "Read a help document by file name, for example welcome.md.",
			InputSchema: map[string]any{"type": "object", "required": []string{"name"},
				"properties": map[string]any{"name": map[string]any{"type": "string", "description": "document file name"}}},
			Handle: func(args map[string]any) (string, bool) {
				name, _ := mcpserver.Str(args, "name")
				p, ok := resolve(docsDir(), name)
				if !ok {
					return "That document is not available.", true
				}
				b, err := os.ReadFile(p)
				if err != nil {
					return "That document is not available.", true
				}
				if len(b) > 4096 {
					b = b[:4096]
				}
				return string(b), false
			},
		},
		{
			Name:        "save_note",
			Description: "Save a short note under a file name.",
			InputSchema: map[string]any{"type": "object", "required": []string{"name", "content"},
				"properties": map[string]any{
					"name":    map[string]any{"type": "string", "description": "note file name"},
					"content": map[string]any{"type": "string", "maxLength": 1000},
				}},
			Handle: func(args map[string]any) (string, bool) {
				name, _ := mcpserver.Str(args, "name")
				content, _ := mcpserver.Str(args, "content")
				if len(content) > 1000 {
					return "Note too long.", true
				}
				p, ok := resolve(notesDir(), name)
				if !ok {
					return "Invalid note name.", true
				}
				if err := os.WriteFile(p, []byte(content), 0o666); err != nil {
					return "Could not save the note.", true
				}
				return "Saved.", false
			},
		},
	})
}
