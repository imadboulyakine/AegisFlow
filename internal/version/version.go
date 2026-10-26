// Package version exposes build metadata for the aegisflow binary.
//
// Release builds inject the values with -ldflags, for example:
//
//	go build -ldflags "-X github.com/imadboulyakine/aegisflow/internal/version.Version=v0.1.0 \
//	  -X github.com/imadboulyakine/aegisflow/internal/version.Commit=$(git rev-parse HEAD) \
//	  -X github.com/imadboulyakine/aegisflow/internal/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
//
// When a value is not injected, Get falls back to the VCS metadata the Go toolchain
// embeds (runtime/debug.ReadBuildInfo), so `go build` / `go run` still report something useful.
package version

import (
	"runtime"
	"runtime/debug"
	"sync"
)

// Set via -ldflags "-X ...". Keep them as plain string variables (not constants).
var (
	Version   = ""
	Commit    = ""
	BuildDate = ""
)

const unknown = "unknown"

// Info is the build metadata served by GET /api/v1/version.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"`
	GoVersion string `json:"goVersion"`
	// Modified reports a build from a dirty working tree (only known from VCS info).
	Modified bool `json:"modified,omitzero"`
}

var cached = sync.OnceValue(func() Info {
	bi, _ := debug.ReadBuildInfo() // nil when the binary has no build info
	return resolve(Info{Version: Version, Commit: Commit, BuildDate: BuildDate}, bi)
})

// Get returns the build metadata, computed once per process.
func Get() Info { return cached() }

// resolve fills empty ldflags values from the toolchain-embedded build info.
func resolve(info Info, bi *debug.BuildInfo) Info {
	info.GoVersion = runtime.Version()
	if bi != nil {
		if bi.GoVersion != "" {
			info.GoVersion = bi.GoVersion
		}
		if info.Version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			info.Version = bi.Main.Version
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = s.Value
				}
			case "vcs.time":
				if info.BuildDate == "" {
					info.BuildDate = s.Value
				}
			case "vcs.modified":
				info.Modified = s.Value == "true"
			}
		}
	}
	if info.Version == "" {
		info.Version = "dev"
	}
	if info.Commit == "" {
		info.Commit = unknown
	}
	if info.BuildDate == "" {
		info.BuildDate = unknown
	}
	return info
}
