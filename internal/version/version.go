// Package version holds build metadata stamped in by the release workflow.
package version

// These are set with -ldflags at release time.
var (
	Version = "0.0.0-dev"
	Commit  = "unknown"
)
