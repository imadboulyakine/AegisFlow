// Package webui embeds the production build of the React dashboard (web/).
//
// `make web-build` (bun run build) writes the bundle into ./dist. Only dist/.gitkeep is
// committed, so a fresh clone still compiles; the server then serves a small fallback
// page explaining how to build the frontend.
package webui

import (
	"embed"
	"fmt"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS returns the built frontend rooted at the dist directory.
func FS() (fs.FS, error) {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil, fmt.Errorf("webui: open embedded dist: %w", err)
	}
	return sub, nil
}
