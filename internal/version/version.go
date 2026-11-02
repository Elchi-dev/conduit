// Package version holds build metadata injected at link time.
//
//	go build -ldflags "-X github.com/elchi-dev/conduit/internal/version.Version=v0.1.0"
package version

import "runtime"

var (
	// Version is the semantic version of this build ("dev" for local builds).
	Version = "dev"
	// Commit is the git commit the binary was built from.
	Commit = "unknown"
	// Date is the build timestamp in RFC 3339.
	Date = "unknown"
)

// Info is the JSON shape returned by /version endpoints.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
	Go      string `json:"go"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

// Get returns the build info of the running binary.
func Get() Info {
	return Info{Version, Commit, Date, runtime.Version(), runtime.GOOS, runtime.GOARCH}
}
