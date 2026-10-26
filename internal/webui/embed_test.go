package webui

import (
	"io/fs"
	"testing"
)

func TestFSIsRootedAtDist(t *testing.T) {
	t.Parallel()

	fsys, err := FS()
	if err != nil {
		t.Fatalf("FS() error: %v", err)
	}
	// dist/.gitkeep is committed, so it must exist even before the frontend is built.
	if _, err := fs.Stat(fsys, ".gitkeep"); err != nil {
		t.Fatalf("FS() should be rooted at dist/: %v", err)
	}
	// If the frontend has been built, the entry point must sit at the root.
	if _, err := fs.Stat(fsys, "assets"); err == nil {
		if _, err := fs.Stat(fsys, "index.html"); err != nil {
			t.Errorf("assets/ present but index.html missing: %v", err)
		}
	}
}
