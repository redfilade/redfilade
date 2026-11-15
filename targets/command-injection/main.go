// Command command-injection is a Range target: a network diagnostics tool.
//
//	vulnerable: the host is pasted into a shell command line, so ";", "&&",
//	            "|", "$(...)" and backticks run extra commands
//	secure:     the host must be a hostname or IP address, and the command is
//	            built as an argument list, never parsed by a shell
//
// The cell image has no shell, so the vulnerable build passes its command line
// to a small built-in shell emulator. The emulator is deliberately unsafe in
// the same way a real "sh -c" would be, but it only knows a few read-only
// commands. Deliberately vulnerable in its vulnerable build. Run it only in a
// Redfilade cell.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/redfilade/redfilade/targets/internal/mcpserver"
)

var mode = "secure"

var hostRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$|^[0-9a-fA-F:]{2,39}$`)

func main() {
	mcpserver.Serve("redfilade-target-command-injection", []mcpserver.Tool{{
		Name:        "ping_host",
		Description: "Check whether a host is reachable.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{
			"host": map[string]any{"type": "string", "description": "hostname or IP address to ping"},
		}, "required": []string{"host"}},
		Handle: func(args map[string]any) (string, bool) {
			host, _ := mcpserver.Str(args, "host")
			if mode == "vulnerable" {
				// The classic mistake: build a command line by string concatenation.
				return sh("ping -c 1 " + host), false
			}
			if !hostRe.MatchString(host) {
				return "invalid host: use a hostname or an IP address", true
			}
			return ping([]string{"-c", "1", host}), false
		},
	}})
}

// ping pretends to ping: the cell has no network.
func ping(argv []string) string {
	host := argv[len(argv)-1]
	return fmt.Sprintf("PING %s: 1 packet transmitted, 0 received, 100%% packet loss (no network in this cell)", host)
}

// --- deliberately unsafe shell emulator (vulnerable build only) -------------

// sh interprets a command line roughly the way "sh -c" would: command
// substitution first, then ";", "&&", "||", "|" and newlines separate commands.
func sh(line string) string {
	line = substitute(line)
	var out []string
	for _, cmd := range regexp.MustCompile(`;|&&|\|\||\||\n`).Split(line, -1) {
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}
		out = append(out, run(strings.Fields(cmd)))
	}
	return strings.Join(out, "\n")
}

var (
	dollarSub   = regexp.MustCompile(`\$\(([^()]*)\)`)
	backtickSub = regexp.MustCompile("`([^`]*)`")
)

func substitute(line string) string {
	for _, re := range []*regexp.Regexp{dollarSub, backtickSub} {
		line = re.ReplaceAllStringFunc(line, func(m string) string {
			inner := re.FindStringSubmatch(m)[1]
			return strings.TrimSpace(sh(inner))
		})
	}
	return line
}

func run(argv []string) string {
	switch argv[0] {
	case "ping":
		return ping(argv[1:])
	case "echo":
		return strings.Join(argv[1:], " ")
	case "id":
		return "uid=65532 gid=65532"
	case "whoami":
		return "nonroot"
	case "uname":
		return "Linux"
	case "env":
		env := os.Environ()
		sort.Strings(env)
		return strings.Join(env, "\n")
	case "cat":
		var parts []string
		for _, p := range argv[1:] {
			b, err := os.ReadFile(cellPath(p))
			if err != nil {
				parts = append(parts, "cat: "+p+": No such file or directory")
				continue
			}
			if len(b) > 64<<10 {
				b = b[:64<<10]
			}
			parts = append(parts, string(b))
		}
		return strings.Join(parts, "")
	case "ls":
		dir := "/world"
		if len(argv) > 1 {
			dir = argv[len(argv)-1]
		}
		entries, err := os.ReadDir(cellPath(dir))
		if err != nil {
			return "ls: cannot access '" + dir + "': No such file or directory"
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		return strings.Join(names, "\n")
	default:
		return "sh: " + argv[0] + ": not found"
	}
}

// cellPath maps /world to the run's world directory (the same place inside a
// real cell; a temporary folder in the CLI's own tests).
func cellPath(p string) string {
	if p == "/world" || strings.HasPrefix(p, "/world/") {
		return filepath.Join(mcpserver.WorldDir(), strings.TrimPrefix(p, "/world"))
	}
	return p
}
