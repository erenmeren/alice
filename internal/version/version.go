// Package version exposes build information injected at link time.
package version

// These are overridden with -ldflags "-X alice/internal/version.Version=..." at build time.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// Info is the build information returned by the API.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
}

// Get returns the current build information.
func Get() Info {
	return Info{Version: Version, Commit: Commit, BuildTime: BuildTime}
}
