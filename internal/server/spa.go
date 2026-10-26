package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"
)

const (
	cacheImmutable  = "public, max-age=31536000, immutable"
	cacheRevalidate = "no-cache"
	indexFile       = "index.html"
)

// hashedAsset matches content-hashed bundle output such as assets/index-j5bd2x86.js
// (see web/scripts/build.ts naming). Only these are safe to cache forever.
var hashedAsset = regexp.MustCompile(`^assets/(?:.+/)?[^/]+-[A-Za-z0-9]{8,}\.[A-Za-z0-9.]+$`)

// contentTypes is an explicit allow-list so responses never depend on the host's
// mime.types files or on content sniffing.
var contentTypes = map[string]string{
	".html":        "text/html; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".json":        "application/json",
	".map":         "application/json",
	".webmanifest": "application/manifest+json",
	".txt":         "text/plain; charset=utf-8",
	".svg":         "image/svg+xml",
	".png":         "image/png",
	".jpg":         "image/jpeg",
	".jpeg":        "image/jpeg",
	".gif":         "image/gif",
	".webp":        "image/webp",
	".avif":        "image/avif",
	".ico":         "image/x-icon",
	".woff":        "font/woff",
	".woff2":       "font/woff2",
	".wasm":        "application/wasm",
}

// fallbackHTML is served when the binary was built without the frontend. It contains
// no inline script or style so it also complies with the CSP.
const fallbackHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AegisFlow</title>
</head>
<body>
<h1>AegisFlow</h1>
<p>The API is running, but the web dashboard was not built into this binary.</p>
<p>Run <code>make build</code> (or <code>make web-build</code> followed by <code>make go-build</code>) to embed it.</p>
<p>Endpoints: <a href="/healthz">/healthz</a> &middot; <a href="/readyz">/readyz</a> &middot; <a href="/api/v1/version">/api/v1/version</a></p>
</body>
</html>
`

type staticAsset struct {
	body         []byte
	contentType  string
	cacheControl string
	etag         string
}

// spaHandler serves the embedded single-page app. Files are loaded into memory once at
// startup (the bundle is small), so requests never touch a filesystem and path
// traversal is impossible: lookups are exact map hits on cleaned paths.
type spaHandler struct {
	assets map[string]*staticAsset
	index  *staticAsset
}

func newSPAHandler(fsys fs.FS) (*spaHandler, error) {
	h := &spaHandler{assets: map[string]*staticAsset{}}
	if fsys != nil {
		err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if isHidden(name) {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			body, err := fs.ReadFile(fsys, name)
			if err != nil {
				return err
			}
			h.assets[name] = newStaticAsset(name, body)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if idx, ok := h.assets[indexFile]; ok {
		h.index = idx
	} else {
		h.index = newStaticAsset(indexFile, []byte(fallbackHTML))
	}
	return h, nil
}

func newStaticAsset(name string, body []byte) *staticAsset {
	sum := sha256.Sum256(body)
	cache := cacheRevalidate
	if hashedAsset.MatchString(name) {
		cache = cacheImmutable
	}
	return &staticAsset{
		body:         body,
		contentType:  contentTypeFor(name),
		cacheControl: cache,
		etag:         `"` + hex.EncodeToString(sum[:16]) + `"`,
	}
}

func contentTypeFor(name string) string {
	ext := strings.ToLower(path.Ext(name))
	if ct, ok := contentTypes[ext]; ok {
		return ct
	}
	if ct := mime.TypeByExtension(ext); ct != "" {
		return ct
	}
	return "application/octet-stream"
}

// isHidden reports whether any path element is a dotfile (e.g. dist/.gitkeep).
func isHidden(name string) bool {
	if name == "." {
		return false
	}
	for elem := range strings.SplitSeq(name, "/") {
		if strings.HasPrefix(elem, ".") {
			return true
		}
	}
	return false
}

func (h *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	asset, ok := h.assets[name]
	switch {
	case ok:
	case name == "" || name == indexFile:
		asset = h.index
	case isHidden(name) || path.Ext(name) != "":
		// Dotfiles are never served. Anything else that looks like a file (e.g.
		// /favicon.ico, /assets/old-hash.js) gets a real 404, never index.html, so stale
		// or mistyped asset URLs fail loudly instead of being parsed as HTML.
		w.Header().Set("Cache-Control", cacheRevalidate)
		http.NotFound(w, r)
		return
	default:
		// Client-side route such as /vulnerabilities: let the React router handle it.
		asset = h.index
	}

	hdr := w.Header()
	hdr.Set("Content-Type", asset.contentType)
	hdr.Set("Cache-Control", asset.cacheControl)
	hdr.Set("ETag", asset.etag)
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(asset.body))
}
