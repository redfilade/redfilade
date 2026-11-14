// Command redfilade is the Redfilade CLI.
//
// Phase 0: only `version` exists. The test command arrives in Phase 1
// (see docs/phase-0.md and the README roadmap).
package main

import (
	"fmt"
	"os"

	"github.com/redfilade/redfilade/internal/version"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Printf("redfilade %s (%s)\n", version.Version, version.Commit)
		return
	}
	fmt.Fprintln(os.Stderr, "redfilade: no commands yet; this is the Phase 0 foundation. Try `redfilade version`.")
	os.Exit(2)
}
